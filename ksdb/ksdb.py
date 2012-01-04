from tornado import gen
import socket
import logging
import tornado.iostream
import re
import time
import hashlib
import xml.parsers.expat
import urlparse
import base64
import pdb
import hmac
import urllib
import functools
import base64
from tornado.escape import utf8
from tornado.util import b
from tornado.httputil import HTTPHeaders
from tornado.escape import native_str
from tornado.options import options

def escape(s):
    return urllib.quote(s, safe='-_~')

def urlencode(d):
    # not the same as urllib's urlencode (which makes signatures not match)
    if isinstance(d, dict):
        d = d.iteritems()
    return '&'.join(['%s=%s' % (escape(k), escape(v)) for k, v in d])

def parse_headers(data):
    data = native_str(data.decode("latin1"))
    first_line, _, header_data = data.partition("\n")
    match = re.match("HTTP/1.[01] ([0-9]+)", first_line)
    assert match
    code = int(match.group(1))
    headers = HTTPHeaders.parse(header_data)
    return code, headers

def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)

class ResponseParser(object):
    def __init__(self, data):
        self.results = []
        self.attributes = {}
        self.meta = {}
        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler = self.start_elt
        p.EndElementHandler = self.end_elt
        p.CharacterDataHandler = self.data
        self.stack = []
        self._new_select_result = None
        self._cur_encoding = None
        p.Parse(data)
        if 'NextToken' in self.meta:
            self.meta['NextToken'] = ''.join( self.meta['NextToken'] )

    def start_elt(self, name, attrs):
        if 'encoding' in attrs:
            self._cur_encoding = attrs['encoding']
        self.stack.append(name)

        if self.stack == ['SelectResponse','SelectResult']:
            self._new_select_result = True
        #logging.info('start elt %s %s' % (name, attrs))

    def end_elt(self, name):
        if self._cur_encoding:
            self._cur_encoding = None
        #logging.info('end elt %s' % name)
        if self.stack == ['SelectResponse','SelectResult','Item']:
            self.results.append( { self._new_select_result: self.attributes } )
            self.attributes = {}
            self._new_select_result = None

        self.stack.pop()

    def data(self, data):
        if self.stack == ['SelectResponse','SelectResult','Item','Name']:
            self._new_select_result = data
        elif self.stack[-1] == 'NextToken':
            if 'NextToken' not in self.meta:
                self.meta['NextToken'] = []
            self.meta['NextToken'].append( data.strip() )
        elif len(self.stack) > 2 and self.stack[-2] == 'Attribute':
            #logging.info('got attribute in %s' % self.stack)
            if self._cur_encoding:
                data = base64.b64decode( data )
            if self.stack[-1] == 'Name':
                self._cur_name = data
            else:
                if self._cur_name in self.attributes:
                    if len(self.stack) > 1 and self.stack[1] == 'GetAttributesResult':
                        # &amp; causes data to be called multiple
                        # times even for inside a single thing
                        self.attributes[self._cur_name] += data
                    else:
                        if hasattr( self.attributes[self._cur_name], '__iter__' ):
                            self.attributes[self._cur_name].append( data )
                        else:
                            self.attributes[self._cur_name] = [ self.attributes[self._cur_name], data ]
                else:
                    self.attributes[self._cur_name] = data
        elif len(self.stack) > 2 and self.stack[-2] == 'DomainMetadataResult':
            self.attributes[self.stack[-1]] = data
        elif self.stack[-1] == 'DomainName':
            if 'DomainName' not in self.attributes:
                self.attributes['DomainName'] = []
            self.attributes['DomainName'].append( data )
        elif self.stack[-1] in ['BoxUsage', 'RequestId']:
            self.meta[self.stack[-1]] = data
        else:
            logging.info('%s data %s' % (self.stack, data))

class SignatureMethod(object):
    def build_signature_base_string(self, request):
        sig = '\n'.join( (
            request.get_normalized_http_method(),
            request.get_normalized_http_host(),
            request.get_normalized_http_path(),
            request.get_normalized_parameters(),
            ) )
        return sig


class SignatureMethod_HMAC_SHA256(SignatureMethod):
    name = 'HmacSHA256'
    version = '2'

    def build_signature(self, request, aws_secret):
        base = self.build_signature_base_string(request)
        hashed = hmac.new(aws_secret, base, hashlib.sha256)
        return base64.b64encode(hashed.digest())

signer = SignatureMethod_HMAC_SHA256()

class SDBRequest(object):
    def __init__(self, method, host, parameters=None):
        self.method = method
        self.host = host
        self.parameters = parameters or {}
        self.headers  = { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8', 
                          'Host': host }

    def to_postdata(self):
        return urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in self.parameters.iteritems()])

    def get_normalized_parameters(self):
        """
        Returns a list constisting of all the parameters required in the
        signature in the proper order.

        """
        return urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in 
                            sorted(self.parameters.iteritems()) 
                            if k != 'Signature'])

    def get_normalized_http_method(self):
        return self.method.upper()

    def get_normalized_http_path(self):
        return '/'

    def get_normalized_http_host(self):
        return self.host.lower()

    def set_parameter(self, name, value):
        self.parameters[name] = value

    def generate_timestamp(self):
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())

    def sign_request(self, aws_key, aws_secret):
        self.set_parameter('AWSAccessKeyId', aws_key)
        self.set_parameter('SignatureVersion', signer.version)
        self.set_parameter('SignatureMethod', signer.name)
        self.set_parameter('Timestamp', self.generate_timestamp())
        self.set_parameter('Signature', signer.build_signature(self, aws_secret))

    def make_request_headers(self):
        req_path = '/'
        request_lines = [utf8("%s %s HTTP/1.1" % (self.method,
                                                  req_path))]
        for k, v in self.headers.items():
            line = utf8(k) + b(": ") + utf8(v)
            request_lines.append(line)
        toreturn = b("\r\n").join(request_lines) + b("\r\n\r\n")
        return toreturn
        #if self.request.body is not None:
        #    self.stream.write(self.request.body)

class Response(object):
    def __init__(self, code, headers, body):
        self.code = code
        self.headers = headers
        self.error = self.code != 200
        if 'debug' in options and options.debug:
            self.body = body
        self.attributes = None
        self.parsexml(body)

    def parsexml(self, body):
        parser = ResponseParser(body)
        self.attributes = parser.attributes
        self.meta = parser.meta
        self.results = parser.results

    def get(self, key, default=None):
        if self.attributes:
            if key in self.attributes:
                return self.attributes[key]
        if default: return default
        

class KSDB(object):

    service_version = '2009-04-15'

    def __init__(self, aws_key, aws_secret, db='sdb.amazonaws.com', secure=True, name=None):
        self.db = db
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.streams = {}
        self.name = name

    @gen.engine
    def get_stream(self, callback):
        found = False
        for stream,v in self.streams.iteritems():
            if not stream._connecting and not stream._current_request and not stream.closed():
                found = True
                logging.info('%sfound usable db connection (%s total)' % (self.name+' ' if self.name else '', len(self.streams)))
                callback(stream)
                break
        if not found:
            logging.info('%screating new db connection' % (self.name+' ' if self.name else ''))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            stream = tornado.iostream.IOStream(s)
            stream._current_request = None
            stream.set_close_callback(functools.partial(self.on_close, stream))
            yield gen.Task( stream.connect, (self.db, 80) )
            stream._debug_info = 'ksdb stream'
            self.streams[ stream ] = None
            callback(stream)

    def create_request(self, parameters):
        request = SDBRequest('POST', self.db)
        request.set_parameter('Version', self.service_version)
        request.parameters.update( parameters )
        request.sign_request(self.aws_key, self.aws_secret)
        return request

    def get(self, domain, key, callback):
        data = {
            'Action': 'GetAttributes',
            'DomainName': domain,
            'ItemName': key,
        }
        self.do_request(data, callback)

    def delete_attributes(self, *args, **kwargs):
        return self.delete(*args, **kwargs)

    def delete(self, domain, key, attributes=None, callback=None):
        if attributes is None:
            attributes = {}
        data = {
            'Action': 'DeleteAttributes',
            'DomainName': domain,
            'ItemName': key,
        }
        idx = 0
        for name, value in attributes.iteritems():
            if hasattr(value, '__iter__'):
                values = value
            else:
                values = [value]
            for value in values:
                data['Attribute.%s.Name' % idx] = name
                data['Attribute.%s.Value' % idx] = value
                idx += 1
        self.do_request(data, callback)

    def batch_put(self, domain, items, callback=None):
        data = {
            'Action': 'BatchPutAttributes',
            'DomainName': domain,
        }
        item_idx = 0
        for domainkey, item in items.iteritems():

            data['Item.%s.ItemName' % item_idx] = domainkey
            attr_idx = 0
            for k, v in item.items():
                if hasattr(v,'__iter__'):
                    values = v
                else:
                    values = [v]
                for value in values:
                    data['Item.%s.Attribute.%s.Name' % (item_idx, attr_idx)] = k
                    data['Item.%s.Attribute.%s.Value' % (item_idx, attr_idx)] = v
                    attr_idx += 1

            item_idx += 1
        self.do_request(data, callback)                

    def put_attributes(self, *args, **kwargs):
        self.put(*args, **kwargs)

    def put(self, domain, key, attributes, callback=None, replace=True):
        attributes = attributes.items()

        #logging.info('put %s' % attributes)
        data = {
            'Action': 'PutAttributes',
            'DomainName': domain,
            'ItemName': key,
        }
        idx = 0
        for attribute in attributes:
            name = attribute[0]
            values = attribute[1]
            if not hasattr(values, '__iter__') or isinstance(values, basestring):
                values = [values]
            for value in values:
                #value = self.encoder.encode(domain, name, value)
                data['Attribute.%s.Name' % idx] = name
                data['Attribute.%s.Value' % idx] = value
                if len(attribute) == 2 or attribute[2] and replace:
                    data['Attribute.%s.Replace' % idx] = 'true' if replace else 'false'
                idx += 1
        #for k in sorted(data):
        #    logging.info('put creates data %s %s' % (k,data[k]))
        self.do_request(data, callback)

    def remove_connection(self, stream):
        if not stream.closed(): stream.close()
        if stream in self.streams:
            del self.streams[stream]

    def on_close(self, stream):
        logging.warn('db connection close')
        if stream._current_request:
            # likely "read error" on socket iostream.py
            if stream._current_request:
                logging.error('db connection closed while had _current_request')
        self.remove_connection(stream)

    @gen.engine
    def do_request(self, arguments, callback=None):
        if 'Action' in arguments:
            if arguments['Action'] == 'GetAttributes':
                logging.info('do request %s %s' % (arguments['Action'], arguments['ItemName']))
            else:
                logging.info('do request %s' % arguments['Action'])
        stream = yield gen.Task( self.get_stream )
        request = self.create_request(arguments)
        stream._current_request = request
        body = request.to_postdata()
        request.headers['Content-Length'] = str(len(body))
        towrite = request.make_request_headers() + body
        #logging.info('writing %s' % towrite)
        yield gen.Task( stream.write, towrite )
        rawheaders = yield gen.Task( stream.read_until, '\r\n\r\n' )

        code, headers = parse_headers(rawheaders)
        if code != 200:
            logging.error('got error response %s, %s' % (code, headers))
        #logging.info('got headers %s' % headers)
        #logging.info('got resp headers %s' % headers)
        data = yield gen.Task( stream.read_until, '\r\n' )

        chunks = []
        while True:
            length = int(data.strip(), 16)
            if length > 0:
                chunk = yield gen.Task( stream.read_bytes, length + 2 )
                #logging.info('read chunk')
                chunks.append(chunk[:-2])
                data = yield gen.Task( stream.read_until, '\r\n' )
            else:
                # keep-alive -- read off last \r\n
                yield gen.Task( stream.read_until, '\r\n' )
                break

        stream._current_request = None
        #stream.close()
        resp = Response(code, headers, ''.join(chunks))
        callback( resp )

        if len(self.streams) > 25:
            logging.warn('too many db connections %s -- closing one' % len(self.streams))
            self.remove_connection(stream)

        #logging.info('chunks %s' % chunks)
        #resp.parsexml()

        #callback( resp )


    def get_domain(self, name):
        return Domain(self, name)

    def create_domain(self, name, callback):
        data = {
            'Action': 'CreateDomain',
            'DomainName': name,
        }
        self.do_request(data, callback)

    def delete_domain(self, name, callback):
        data = {
            'Action': 'DeleteDomain',
            'DomainName': name,
        }
        self.do_request(data, callback)

    def list_domains(self, callback):
        data = {
            'Action': 'ListDomains',
            'MaxNumberOfDomains': '100',
        }
        self.do_request(data, callback)

    def query(self, expr, callback=None, token=None):
        data = {
            'Action': 'Select',
            'SelectExpression': expr,
        }
        if token:
            data['NextToken'] = token
        self.do_request(data, callback)

class Domain(object):
    def __init__(self, db, domain):
        self.db = db
        self.domain = domain

    def get_async(self, key, callback):
        return self.get(key, callback)

    def get(self, key, callback):
        self.db.get(self.domain, key, callback)

    def put(self, key, attributes, callback):
        self.db.put(self.domain, key, attributes, callback)

    def batch_put(self, items, callback):
        self.db.batch_put(self.domain, items, callback)

    def delete(self, key, attributes=None, callback=None):
        self.db.delete(self.domain, key, attributes=attributes, callback=callback)

    def get_metadata(self, callback):
        data = {
            'Action': 'DomainMetadata',
            'DomainName': self.domain,
        }
        self.db.do_request(data, callback)

    def get_by_attribute(self, attrname, attrval, callback):
        self.db.query('select * from %s where %s="%s"' % (self.domain, attrname, attrval), callback)
