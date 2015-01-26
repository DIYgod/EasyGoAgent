#!/usr/bin/env python
# coding:utf-8

raise NotImplementedError('Coming soon...')

__version__ = '3.1.18'

import sys
import os
import glob

reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))

try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import errno
import time
import struct
import collections
import zlib
import httplib
import re
import io
import fnmatch
import random
import base64
import uuid
import urlparse
import threading
import thread
import socket
import ssl
import Queue
import ConfigParser
import urllib2
import OpenSSL
import dnslib
import logging

NetWorkIOError = (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


from proxylib import LRUCache
from proxylib import CertUtil
from proxylib import dnslib_resolve_over_tcp
from proxylib import dnslib_resolve_over_udp
from proxylib import dnslib_record2iplist
from proxylib import SSLConnection
from proxylib import ProxyUtil
from proxylib import inflate
from proxylib import deflate
from proxylib import get_dnsserver_list
from proxylib import spawn_later
from proxylib import AuthFilter
from proxylib import AdvancedProxyHandler
from proxylib import BlackholeFilter
from proxylib import UserAgentFilter
from proxylib import URLRewriteFilter
from proxylib import BaseProxyHandlerFilter
from proxylib import CipherFileObject
from proxylib import RC4Cipher
from proxylib import FakeHttpsFilter
from proxylib import ForceHttpsFilter
from proxylib import StaticFileFilter
from proxylib import get_process_list
from proxylib import get_uptime
from proxylib import LocalProxyServer
from proxylib import RangeFetch
from proxylib import SimpleProxyHandlerFilter
from proxylib import SimpleProxyHandler


class MyURLFetch(object):
    """URLFetch for gae/php fetchservers"""

    def __init__(self, fetchserver, create_http_request):
        assert isinstance(fetchserver, basestring) and callable(create_http_request)
        self.fetchserver = fetchserver
        self.create_http_request = create_http_request

    def fetch(self, method, url, headers, body, timeout, **kwargs):
        raise NotImplementedError


class Common(object):
    """Global Config Object"""

    ENV_CONFIG_PREFIX = 'GOAGENT_'

    def __init__(self):
        """load config from server.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.splitext(os.path.abspath(__file__))[0]+'.ini'
        self.CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', self.CONFIG_FILENAME)
        self.CONFIG.read([self.CONFIG_FILENAME, self.CONFIG_USER_FILENAME])

        for key, value in os.environ.items():
            m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % self.ENV_CONFIG_PREFIX, key)
            if m:
                self.CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')
        self.AUTH = dict(self.CONFIG.items('auth'))

        if 'USERDNSDOMAIN' in os.environ and re.match(r'^\w+\.\w+$', os.environ['USERDNSDOMAIN']):
            self.CONFIG.set('profile', '.' + os.environ['USERDNSDOMAIN'], '')

        host_map = collections.OrderedDict()
        host_postfix_map = collections.OrderedDict()
        hostport_map = collections.OrderedDict()
        hostport_postfix_map = collections.OrderedDict()
        urlre_map = collections.OrderedDict()
        withgae_sites = []
        crlf_sites = []
        forcehttps_sites = []
        noforcehttps_sites = []
        fakehttps_sites = []
        nofakehttps_sites = []
        dns_servers = []

        for site, rule in self.CONFIG.items('profile'):
            rules = [x.strip() for x in re.split(r'[,\|]', rule) if x.strip()]
            if site == 'dns':
                dns_servers = rules
                continue
            for name, sites in [('withgae', withgae_sites),
                                ('crlf', crlf_sites),
                                ('forcehttps', forcehttps_sites),
                                ('noforcehttps', noforcehttps_sites),
                                ('fakehttps', fakehttps_sites),
                                ('nofakehttps', nofakehttps_sites)]:
                if name in rules:
                    sites.append(site)
                    rules.remove(name)
            hostname = rules and rules[0]
            if not hostname:
                continue
            if hostname == 'direct':
                hostname = ''
            if ':' in site and '\\' not in site:
                if site.startswith('.'):
                    hostport_postfix_map[site] = hostname
                else:
                    hostport_map[site] = hostname
            elif '\\' in site:
                urlre_map[re.compile(site).match] = hostname
            else:
                if site.startswith('.'):
                    host_postfix_map[site] = hostname
                else:
                    host_map[site] = hostname

        self.DNS_SERVERS = dns_servers
        self.WITHGAE_SITES = set(withgae_sites)
        self.CRLF_SITES = tuple(crlf_sites)
        self.FORCEHTTPS_SITES = tuple(forcehttps_sites)
        self.NOFORCEHTTPS_SITES = set(noforcehttps_sites)
        self.FAKEHTTPS_SITES = tuple(fakehttps_sites)
        self.NOFAKEHTTPS_SITES = set(nofakehttps_sites)
        self.HOSTPORT_MAP = hostport_map
        self.HOSTPORT_POSTFIX_MAP = hostport_postfix_map
        self.HOSTPORT_POSTFIX_ENDSWITH = tuple(self.HOSTPORT_POSTFIX_MAP)
        self.URLRE_MAP = urlre_map
        self.HOST_MAP = host_map
        self.HOST_POSTFIX_MAP = host_postfix_map
        self.HOST_POSTFIX_ENDSWITH = tuple(self.HOST_POSTFIX_MAP)

        self.IPLIST_MAP = collections.OrderedDict((k, v.split('|')) for k, v in self.CONFIG.items('iplist'))
        self.IPLIST_MAP.update((k, [k]) for k, v in self.HOST_MAP.items() if k == v)

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

    def extend_iplist(self, iplist_name, hosts):
        logging.info('extend_iplist start for hosts=%s', hosts)
        new_iplist = []
        def do_remote_resolve(host, dnsserver, queue):
            assert isinstance(dnsserver, basestring)
            for dnslib_resolve in (dnslib_resolve_over_udp, dnslib_resolve_over_tcp):
                try:
                    time.sleep(random.random())
                    iplist = dnslib_record2iplist(dnslib_resolve(host, [dnsserver], timeout=4, blacklist=()))
                    queue.put((host, dnsserver, iplist))
                except (socket.error, OSError) as e:
                    logging.warning('%r remote host=%r failed: %s', dnslib_resolve, host, e)
                    time.sleep(1)
        result_queue = Queue.Queue()
        for host in hosts:
            for dnsserver in self.DNS_SERVERS:
                logging.debug('remote resolve host=%r from dnsserver=%r', host, dnsserver)
                thread.start_new_thread(do_remote_resolve, (host, dnsserver, result_queue))
        for _ in xrange(len(self.DNS_SERVERS) * len(hosts) * 2):
            try:
                host, dnsserver, iplist = result_queue.get(timeout=16)
                logging.debug('%r remote host=%r return %s', dnsserver, host, iplist)
                new_iplist += iplist
            except Queue.Empty:
                break
        logging.info('extend_iplist finished, added %s', len(set(self.IPLIST_MAP[iplist_name])-set(new_iplist)))
        self.IPLIST_MAP[iplist_name] = list(set(self.IPLIST_MAP[iplist_name] + new_iplist))

    def resolve_iplist(self):
        # https://support.google.com/websearch/answer/186669?hl=zh-Hans
        def do_local_resolve(host, queue):
            assert isinstance(host, basestring)
            for _ in xrange(3):
                try:
                    queue.put((host, socket.gethostbyname_ex(host)[-1]))
                except (socket.error, OSError) as e:
                    logging.warning('socket.gethostbyname_ex host=%r failed: %s', host, e)
                    time.sleep(0.1)
        google_blacklist = ['216.239.32.20']
        for name, need_resolve_hosts in list(self.IPLIST_MAP.items()):
            if all(re.match(r'\d+\.\d+\.\d+\.\d+', x) or ':' in x for x in need_resolve_hosts):
                continue
            need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not re.match(r'\d+\.\d+\.\d+\.\d+', x)]
            resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
            result_queue = Queue.Queue()
            for host in need_resolve_remote:
                logging.debug('local resolve host=%r', host)
                thread.start_new_thread(do_local_resolve, (host, result_queue))
            for _ in xrange(len(need_resolve_remote)):
                try:
                    host, iplist = result_queue.get(timeout=8)
                    resolved_iplist += iplist
                except Queue.Empty:
                    break
            if name == 'google_hk':
                for delay in (1, 60, 150, 240, 300, 450, 600, 900):
                    spawn_later(delay, self.extend_iplist, name, need_resolve_remote)
            if name.startswith('google_') and name not in ('google_cn', 'google_hk') and resolved_iplist:
                iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
            else:
                resolved_iplist = list(set(resolved_iplist))
            if name.startswith('google_'):
                resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
            if len(resolved_iplist) == 0:
                logging.error('resolve %s host return empty! please retry!', name)
                sys.exit(-1)
            logging.info('resolve name=%s host to iplist=%r', name, resolved_iplist)
            common.IPLIST_MAP[name] = resolved_iplist

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'DNS Servers        : %s\n' % '|'.join(common.DNS_SERVERS)
        info += '------------------------------------------------------\n'
        return info

common = Common()


class HostsFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter_localfile(self, handler, filename):
        content_type = None
        try:
            import mimetypes
            content_type = mimetypes.types_map.get(os.path.splitext(filename)[1])
        except StandardError as e:
            logging.error('import mimetypes failed: %r', e)
        try:
            with open(filename, 'rb') as fp:
                data = fp.read()
                headers = {'Connection': 'close', 'Content-Length': str(len(data))}
                if content_type:
                    headers['Content-Type'] = content_type
                return [handler.MOCK, 200, headers, data]
        except StandardError as e:
            return [handler.MOCK, 403, {'Connection': 'close'}, 'read %r %r' % (filename, e)]

    def filter(self, handler):
        host, port = handler.host, handler.port
        hostport = handler.path if handler.command == 'CONNECT' else '%s:%d' % (host, port)
        hostname = ''
        if host in common.HOST_MAP:
            hostname = common.HOST_MAP[host] or host
        elif host.endswith(common.HOST_POSTFIX_ENDSWITH):
            hostname = next(common.HOST_POSTFIX_MAP[x] for x in common.HOST_POSTFIX_MAP if host.endswith(x)) or host
            common.HOST_MAP[host] = hostname
        if hostport in common.HOSTPORT_MAP:
            hostname = common.HOSTPORT_MAP[hostport] or host
        elif hostport.endswith(common.HOSTPORT_POSTFIX_ENDSWITH):
            hostname = next(common.HOSTPORT_POSTFIX_MAP[x] for x in common.HOSTPORT_POSTFIX_MAP if hostport.endswith(x)) or host
            common.HOSTPORT_MAP[hostport] = hostname
        if handler.command != 'CONNECT' and common.URLRE_MAP:
            try:
                hostname = next(common.URLRE_MAP[x] for x in common.URLRE_MAP if x(handler.path)) or host
            except StopIteration:
                pass
        if not hostname:
            return None
        elif hostname in common.IPLIST_MAP:
            handler.dns_cache[host] = common.IPLIST_MAP[hostname]
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) or ':' in hostname:
            handler.dns_cache[host] = [hostname]
        elif hostname.startswith('file://'):
            filename = hostname.lstrip('file://')
            if os.name == 'nt':
                filename = filename.lstrip('/')
            return self.filter_localfile(handler, filename)
        cache_key = '%s:%s' % (hostname, port)
        if handler.command == 'CONNECT':
            return [handler.FORWARD, host, port, handler.connect_timeout, {'cache_key': cache_key}]
        else:
            if host.endswith(common.CRLF_SITES):
                handler.close_connection = True
                return [handler.DIRECT, {'crlf': True}]
            else:
                return [handler.DIRECT, {'cache_key': cache_key}]


class VPSProxyHandler(AdvancedProxyHandler):
    """GAE Proxy Handler"""
    handler_filters = [SimpleProxyHandlerFilter()]
    urlfetch_class = MyURLFetch

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        logging.info('resolve common.IPLIST_MAP names=%s to iplist', list(common.IPLIST_MAP))
        common.resolve_iplist()

    def gethostbyname2(self, hostname):
        for postfix in ('.appspot.com', '.googleusercontent.com'):
            if hostname.endswith(postfix):
                host = common.HOST_MAP.get(hostname) or common.HOST_POSTFIX_MAP[postfix]
                return common.IPLIST_MAP.get(host) or host.split('|')
        return AdvancedProxyHandler.gethostbyname2(self, hostname)

    def handle_urlfetch_error(self, fetchserver, response):
        pass


def pre_start():
    if True:
        VPSProxyHandler.handler_filters.insert(0, HostsFilter())
    if True:
        VPSProxyHandler.handler_filters.insert(0, URLRewriteFilter())
    if common.FAKEHTTPS_SITES:
        VPSProxyHandler.handler_filters.insert(0, FakeHttpsFilter(common.FAKEHTTPS_SITES, common.NOFAKEHTTPS_SITES))
    if common.FORCEHTTPS_SITES:
        VPSProxyHandler.handler_filters.insert(0, ForceHttpsFilter(common.FORCEHTTPS_SITES, common.NOFORCEHTTPS_SITES))
    if common.USERAGENT_ENABLE:
        VPSProxyHandler.handler_filters.insert(0, UserAgentFilter(common.USERAGENT_STRING))
    if common.AUTH:
        VPSProxyHandler.handler_filters.insert(0, AuthFilter('', ''))


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    pre_start()
    sys.stderr.write(common.info())

    HandlerClass = VPSProxyHandler
    server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), HandlerClass)
    server.serve_forever()

if __name__ == '__main__':
    main()
