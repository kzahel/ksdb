import tornado.options
import functools
import time
import tornado.ioloop
from tornado import gen
from tornado.options import define
import uuid

import logging
define('debug',default=True)
tornado.options.parse_command_line()

import pdb


ioloop = tornado.ioloop.IOLoop.instance()

def asyncsleep(t, callback=None):
    logging.info('sleeping %s' % t)
    ioloop.add_timeout( time.time() + t, callback )

def got_user(user, resp):
    if user:
        logging.info(user.serialize())
    else:
        logging.info('got user %s' % user)
import sys

from ksdb.config import config
from ksdb.ksdb import KSDB
db = KSDB(config['sdb_access_key'], config['sdb_access_secret'], secure=False)
users = db.get_domain('users_dev')

@gen.engine
def create_domains(domains):
    yield gen.Multi( [ gen.Task( db.create_domain, domain ) for domain in domains ] )

@gen.engine
def test_create_domain():
    testname = 'testdomain69'
    result = yield gen.Task( db.create_domain, testname )
    yield gen.Task( asyncsleep, 5 )
    result = yield gen.Task( db.list_domains )
    assert testname in result.attributes['DomainName']
    result = yield gen.Task( db.delete_domain, testname )
    yield gen.Task( asyncsleep, 5 )
    result = yield gen.Task( db.list_domains )
    assert testname not in result.attributes['DomainName']
    assert result.code == 200

@gen.engine
def test_query():
    domainname = 'testdomain69'

    result = yield gen.Task( db.create_domain, domainname )
    yield gen.Task( asyncsleep, 1 )

    domain = db.get_domain(domainname)

    items = { 'test key 1': dict( foo = 23,
                                  bar = 29,
                                  caitlyn = 'i am the best',
                                  testval = 'hello',
                                  baz = 31 ),
              'test key 2': dict( baz = 'woot',
                                  testval = 'hello',
                                  bob = 'rar' )
              }

    result = yield gen.Task( domain.batch_put, items )
    yield gen.Task( asyncsleep, 0.5 )

    query = "select * from %s where testval=\"hello\" limit 2" % domainname

    result = yield gen.Task( db.query, query )

    assert map( lambda x: x.keys()[0], result.results ) == ['test key 1', 'test key 2']

    logging.info('got result %s: %s, %s, %s' % (result.code, result.attributes, result.meta, result.results))

    result = yield gen.Task( db.delete_domain, domainname )


@gen.engine
def do_stuff():
    #result = yield gen.Task( users.put, 'blah 2', dict( kyle = 102 ) )
    result = yield gen.Task( db.query, "select * from users where version=\"24979\" limit 2" )
    logging.info('got result %s: %s, %s, %s' % (result.code, result.attributes, result.meta, result.results))
    if 'NextToken' in result.meta:
        result = yield gen.Task( db.query, "select * from users where version=\"24979\" limit 2", result.meta['NextToken'] )
        logging.info('got result %s: %s, %s, %s' % (result.code, result.attributes, result.meta, result.results))
    #result = yield gen.Task( db.query, "select" )


    return
    result = yield gen.Task( users.delete, 'blah2', {'kyle':[1,59,84,85,88,89,90]} )
    #yield gen.Task( asyncsleep, 5 )

    #result = yield gen.Task( users.get, 'blah2' )
    logging.info('got result %s: %s, %s' % (result.code, result.attributes, result.meta))

    result = yield gen.Task( users.get_metadata )
    logging.info('got result %s: %s, %s' % (result.code, result.attributes, result.meta))

    ioloop.stop()

#do_stuff()
#test_query()
#create_domains(['content','content_dev'])

@gen.engine
def setup_channel():
    for domainname in ['content','content_dev']:
        yield gen.Task( db.delete_domain, domainname )

    yield gen.Task( asyncsleep, 5 ) 
    for domainname in ['content','content_dev']:
        yield gen.Task( db.create_domain, domainname )
    yield gen.Task( asyncsleep, 5 ) 

    channel_name = "Toolbar Featured"
    channel_key = str(uuid.uuid4())
    channel = { channel_key: { 'type': 'channel',
                                'name': channel_name,
                                'description': 'torrents featured in the toolbar'
                                } }

    
    for domainname in ['content','content_dev']:
        domain = db.get_domain(domainname)
        yield gen.Task( domain.batch_put, channel )



        inserted = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        key = str(uuid.uuid4())

        yield gen.Task( domain.batch_put, { key: { 'channel': channel_key,
                      'type': 'item',
                      'name': "God's Robots",
                      'torrent': 'http://apps.bittorrent.com/godsrobots/godsrobots.torrent',
                      'created': inserted
                      }} )
                    

setup_channel()

#test_create_domain()
ioloop.start()
