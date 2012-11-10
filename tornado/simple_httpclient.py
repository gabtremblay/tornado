#!/usr/bin/env python
from __future__ import absolute_import, division, with_statement

from tornado.escape import utf8, _unicode, native_str
from tornado.httpclient import HTTPRequest, HTTPResponse, HTTPError, AsyncHTTPClient, main
from tornado.httputil import HTTPHeaders
from tornado.iostream import IOStream, SSLIOStream
from tornado.netutil import Resolver
from tornado.log import gen_log
from tornado import stack_context
from tornado.util import b, GzipDecompressor

import base64
import collections
import contextlib
import copy
import functools
import os.path
import re
import socket
import sys
import time
import urlparse

try:
    from io import BytesIO  # python 3
except ImportError:
    from cStringIO import StringIO as BytesIO  # python 2

try:
    import ssl  # python 2.6+
except ImportError:
    ssl = None

_DEFAULT_CA_CERTS = os.path.dirname(__file__) + '/ca-certificates.crt'


class SimpleAsyncHTTPClient(AsyncHTTPClient):
    """Non-blocking HTTP client with no external dependencies.

    This class implements an HTTP 1.1 client on top of Tornado's IOStreams.
    It does not currently implement all applicable parts of the HTTP
    specification, but it does enough to work with major web service APIs
    (mostly tested against the Twitter API so far).

    This class has not been tested extensively in production and
    should be considered somewhat experimental as of the release of
    tornado 1.2.  It is intended to become the default AsyncHTTPClient
    implementation in a future release.  It may either be used
    directly, or to facilitate testing of this class with an existing
    application, setting the environment variable
    USE_SIMPLE_HTTPCLIENT=1 will cause this class to transparently
    replace tornado.httpclient.AsyncHTTPClient.

    Some features found in the curl-based AsyncHTTPClient are not yet
    supported.  In particular, proxies are not supported, connections
    are not reused, and callers cannot select the network interface to be
    used.

    Python 2.6 or higher is required for HTTPS support.  Users of Python 2.5
    should use the curl-based AsyncHTTPClient if HTTPS support is required.

    """
    def initialize(self, io_loop=None, max_clients=10,
                   hostname_mapping=None, max_buffer_size=104857600,
                   resolver=None):
        """Creates a AsyncHTTPClient.

        Only a single AsyncHTTPClient instance exists per IOLoop
        in order to provide limitations on the number of pending connections.
        force_instance=True may be used to suppress this behavior.

        max_clients is the number of concurrent requests that can be
        in progress.  Note that this arguments are only used when the
        client is first created, and will be ignored when an existing
        client is reused.

        hostname_mapping is a dictionary mapping hostnames to IP addresses.
        It can be used to make local DNS changes when modifying system-wide
        settings like /etc/hosts is not possible or desirable (e.g. in
        unittests).

        max_buffer_size is the number of bytes that can be read by IOStream. It
        defaults to 100mb.
        """
        self.io_loop = io_loop
        self.max_clients = max_clients
        self.queue = collections.deque()
        self.active = {}
        self.hostname_mapping = hostname_mapping
        self.max_buffer_size = max_buffer_size
        self.resolver = resolver or Resolver(io_loop=io_loop)

        # Removeme, dev marker
        self._stream_pool = {}

        # SSl and http
        # pool {
        # index: (scheme, host, port)
        # value : {stream:current_actives}
        # }


    def _build_ssl_options(self, request):
        ssl_options = {}
        if request.validate_cert:
            ssl_options["cert_reqs"] = ssl.CERT_REQUIRED
        if request.ca_certs is not None:
            ssl_options["ca_certs"] = request.ca_certs
        else:
            ssl_options["ca_certs"] = _DEFAULT_CA_CERTS
        if request.client_key is not None:
            ssl_options["keyfile"] = request.client_key
        if request.client_cert is not None:
            ssl_options["certfile"] = request.client_cert

        # SSL interoperability is tricky.  We want to disable
        # SSLv2 for security reasons; it wasn't disabled by default
        # until openssl 1.0.  The best way to do this is to use
        # the SSL_OP_NO_SSLv2, but that wasn't exposed to python
        # until 3.2.  Python 2.7 adds the ciphers argument, which
        # can also be used to disable SSLv2.  As a last resort
        # on python 2.6, we set ssl_version to SSLv3.  This is
        # more narrow than we'd like since it also breaks
        # compatibility with servers configured for TLSv1 only,
        # but nearly all servers support SSLv3:
        # http://blog.ivanristic.com/2011/09/ssl-survey-protocol-support.html
        if sys.version_info >= (2, 7):
            ssl_options["ciphers"] = "DEFAULT:!SSLv2"
        else:
            # This is really only necessary for pre-1.0 versions
            # of openssl, but python 2.6 doesn't expose version
            # information.
            ssl_options["ssl_version"] = ssl.PROTOCOL_SSLv3

        return ssl_options


    def _can_process_request(self, request):
        """
        Test if there's a free stream or if we can spawn a new one
        """
        stream_pool, active_connections = self._get_stream_pool(request)
        if len(stream_pool) > 0:
            return True
        elif active_connections < self.max_clients:
            return True
        else:
            return False


    def _get_stream_pool(self, request):
        """
        Returns the connection pool for a given request based on
        (host, port) target
        """
        pool_id = (request.host, request.port)
        pool_value = self._stream_pool.get(pool_id)

        if not pool_value:
            pool = collections.deque()
            active_connections = 0
            self._stream_pool[pool_id] = (pool, active_connections)
        else:
            pool, active_connections = pool_value

        return pool, active_connections


    def get_stream(self, request, af, socktype, proto):
        """
        Returns a connected free stream if one is available or a new one if not.
        """
        pool_id = (request.host, request.port)
        stream_pool, active_connections = self._get_stream_pool(request)
        if len(stream_pool) > 0:
            free_stream = stream_pool.popleft()
        elif active_connections < self.max_clients:
            # Connect a new stream
            # if connect fail, server does not accept more connections, let just re-queue this request.
            try:
                if request.parsed.scheme == "https":
                    ssl_options = self._build_ssl_options(request)
                    free_stream = SSLIOStream(socket.socket(af, socktype, proto),
                                    io_loop=self.io_loop,
                                    ssl_options=ssl_options,
                                    max_buffer_size=self.max_buffer_size)

                else:
                    free_stream = IOStream(socket.socket(af, socktype, proto),
                                    io_loop=self.io_loop,
                                    max_buffer_size=self.max_buffer_size)

                free_stream.set_close_callback(
                    functools.partial(self._on_stream_close, request))
                active_connections += 1
                self._stream_pool[pool_id] = (stream_pool, active_connections)

            except socket.timeout:
                # Server-side Max connection reached, re-queue requestIOStream
                free_stream = None
        else:
            # No connection available, max clients reached.
            free_stream = None

        return free_stream


    def fetch(self, request, callback, **kwargs):
        if not isinstance(request, HTTPRequest):
            request = HTTPRequest(url=request, **kwargs)
        # We're going to modify this (to add Host, Accept-Encoding, etc),
        # so make sure we don't modify the caller's object.  This is also
        # where normal dicts get converted to HTTPHeaders objects.
        request.headers = HTTPHeaders(request.headers)
        callback = stack_context.wrap(callback)
        self.queue.append((request, callback))
        self._process_queue()
        if self.queue:
            gen_log.debug("max_clients limit reached, request queued. "
                          "%d active, %d queued requests." % (
                    len(self.active), len(self.queue)))


    def _process_queue(self):
        with stack_context.NullContext():
            while self.queue:
                request, callback = self.queue.popleft()

                # Test if we can process the request
                if self._can_process_request(request):
                    _HTTPConnection(self.io_loop, self, request,
                        functools.partial(self._release_fetch, request),
                        callback,
                        self.max_buffer_size)
                else:
                    # No free stream available, re-queue request
                    self.queue.append((request, callback))


    def _release_fetch(self, request):
        pool_id = (request.host, request.port)
        pool, active_connections = self._get_stream_pool(request)
        active_connections -= 1
        self._stream_pool[pool_id] = (pool, active_connections)
        pool.append(request.stream)
        self._process_queue()



    def _on_stream_close(self, request):
        """
        Called when a stream is detected as closed by tornado. This could mean we are done sending requests
        for fitness purposes, if it's the last stream to be closed for a pool_id, we should delete the pool entry.
        """
        pool_id = (request.host, request.port)
        pool, active_connections = self._get_stream_pool(request)
        active_connections -= 1
        if active_connections <= 0:
            del self._stream_pool[pool_id] #fitness
        else:
            self._stream_pool[pool_id] = (pool, active_connections)



class _HTTPConnection(object):
    _SUPPORTED_METHODS = set(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])

    def __init__(self, io_loop, client, request, release_callback,
                 final_callback, max_buffer_size):
        self.start_time = io_loop.time()
        self.io_loop = io_loop
        self.client = client
        self.request = request
        self.release_callback = release_callback
        self.final_callback = final_callback
        self.max_buffer_size = max_buffer_size
        self.code = None
        self.headers = None
        self.chunks = None
        self._decompressor = None
        # Timeout handle returned by IOLoo_on_resp.add_timeout
        self._timeout = None

        if self.client.hostname_mapping is not None:
            self.request.host = \
                self.client.hostname_mapping.get(self.request.host,
                    self.request.host)

        if request.allow_ipv6:
            af = socket.AF_UNSPEC
        else:
            # We only try the first IP we get from getaddrinfo,
            # so restrict to ipv4 by default.
            af = socket.AF_INET

        with stack_context.StackContext(self.cleanup):
            self.client.resolver.getaddrinfo(
                self.request.host, self.request.port, af, socket.SOCK_STREAM,
                0, 0, callback=self._on_resolve)


    def _on_resolve(self, future):
        af, socktype, proto, canonname, sockaddr = future.result()[0]

        # Assign an iostream to the request
        self.request.stream = self.client.get_stream(self.request, af, socktype, proto)

        # Stream acquire failed, re-queue request and exit graceully.
        if not self.request.stream:
            self.client.queue.append((self.request, self.release_callback))
            return

        timeout = min(self.request.connect_timeout, self.request.request_timeout)
        if timeout:
            self._timeout = self.io_loop.add_timeout(
                self.start_time + timeout,
                stack_context.wrap(self._on_timeout))
        self.request.stream.set_close_callback(self._on_close)
        self.request.stream.connect(sockaddr, self._on_connect)


    def _on_timeout(self):
        self._timeout = None
        if self.final_callback is not None:
            raise HTTPError(599, "Timeout")

    def _on_connect(self):
        if self._timeout is not None:
            self.io_loop.remove_timeout(self._timeout)
            self._timeout = None
        if self.request.request_timeout:
            self._timeout = self.io_loop.add_timeout(
                self.start_time + self.request.request_timeout,
                stack_context.wrap(self._on_timeout))
        if (self.request.validate_cert and
            isinstance(self.request.stream, SSLIOStream)):
            match_hostname(self.request.stream.socket.getpeercert(),
                           # ipv6 addresses are broken (in
                           # self.parsed.hostname) until 2.7, here is
                           # correctly parsed value calculated in
                           # __init__
                           self.request.parsed_hostname)
        if (self.request.method not in self._SUPPORTED_METHODS and
            not self.request.allow_nonstandard_methods):
            raise KeyError("unknown method %s" % self.request.method)
        for key in ('network_interface',
                    'proxy_host', 'proxy_port',
                    'proxy_username', 'proxy_password'):
            if getattr(self.request, key, None):
                raise NotImplementedError('%s not supported' % key)
        if "Connection" not in self.request.headers:
            self.request.headers["Connection"] = "close"
        if "Host" not in self.request.headers:
            if '@' in self.request.parsed.netloc:
                self.request.headers["Host"] = self.request.parsed.netloc.rpartition('@')[-1]
            else:
                self.request.headers["Host"] = self.request.parsed.netloc
        username, password = None, None
        if self.request.parsed.username is not None:
            username, password = self.request.parsed.username, \
                                 self.request.parsed.password
        elif self.request.auth_username is not None:
            username = self.request.auth_username
            password = self.request.auth_password or ''
        if username is not None:
            auth = utf8(username) + b(":") + utf8(password)
            self.request.headers["Authorization"] = (b("Basic ") +
                                                     base64.b64encode(auth))
        if self.request.user_agent:
            self.request.headers["User-Agent"] = self.request.user_agent
        if not self.request.allow_nonstandard_methods:
            if self.request.method in ("POST", "PATCH", "PUT"):
                assert self.request.body is not None
            else:
                assert self.request.body is None
        if self.request.body is not None:
            self.request.headers["Content-Length"] = str(len(
                    self.request.body))
        if (self.request.method == "POST" and
            "Content-Type" not in self.request.headers):
            self.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.request.use_gzip:
            self.request.headers["Accept-Encoding"] = "gzip"
        req_path = ((self.request.parsed.path or '/') +
                (('?' + self.request.parsed.query) if self.request.parsed.query else ''))
        request_lines = [utf8("%s %s HTTP/1.1" % (self.request.method,
                                                  req_path))]
        for k, v in self.request.headers.get_all():
            line = utf8(k) + b(": ") + utf8(v)
            if b('\n') in line:
                raise ValueError('Newline in header: ' + repr(line))
            request_lines.append(line)
        self.request.stream.write(b("\r\n").join(request_lines) + b("\r\n\r\n"))
        if self.request.body is not None:
            self.request.stream.write(self.request.body)
        self.request.stream.read_until_regex(b("\r?\n\r?\n"), self._on_headers)

    def _release(self):
        if self.release_callback is not None:
            release_callback = self.release_callback
            self.release_callback = None
            release_callback()

    def _run_callback(self, response):
        self._release()
        if self.final_callback is not None:
            final_callback = self.final_callback
            self.final_callback = None
            final_callback(response)

    @contextlib.contextmanager
    def cleanup(self):
        try:
            yield
        except Exception, e:
            gen_log.warning("uncaught exception", exc_info=True)
            self._run_callback(HTTPResponse(self.request, 599, error=e,
                                request_time=self.io_loop.time() - self.start_time,
                                ))
            if hasattr(self, "stream"):
                self.stream.close()

    def _on_close(self):
        if self.final_callback is not None:
            message = "Connection closed"
            if self.client.stream.error:
                message = str(self.client.stream.error)
            raise HTTPError(599, message)

    def _on_headers(self, data):
        data = native_str(data.decode("latin1"))
        first_line, _, header_data = data.partition("\n")
        match = re.match("HTTP/1.[01] ([0-9]+) ([^\r]*)", first_line)
        assert match
        code = int(match.group(1))
        if 100 <= code < 200:
            self.request.stream.read_until_regex(b("\r?\n\r?\n"), self._on_headers)
            return
        else:
            self.code = code
            self.reason = match.group(2)
        self.headers = HTTPHeaders.parse(header_data)

        if "Content-Length" in self.headers:
            if "," in self.headers["Content-Length"]:
                # Proxies sometimes cause Content-Length headers to get
                # duplicated.  If all the values are identical then we can
                # use them but if they differ it's an error.
                pieces = re.split(r',\s*', self.headers["Content-Length"])
                if any(i != pieces[0] for i in pieces):
                    raise ValueError("Multiple unequal Content-Lengths: %r" %
                                     self.headers["Content-Length"])
                self.headers["Content-Length"] = pieces[0]
            content_length = int(self.headers["Content-Length"])
        else:
            content_length = None

        if self.request.header_callback is not None:
            for k, v in self.headers.get_all():
                self.request.header_callback("%s: %s\r\n" % (k, v))

        if self.request.method == "HEAD":
            # HEAD requests never have content, even though they may have
            # content-length headers
            self._on_body(b(""))
            return
        if 100 <= self.code < 200 or self.code in (204, 304):
            # These response codes never have bodies
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3
            if ("Transfer-Encoding" in self.headers or
                content_length not in (None, 0)):
                raise ValueError("Response with code %d should not have body" %
                                 self.code)
            self._on_body(b(""))
            return

        if (self.request.use_gzip and
            self.headers.get("Content-Encoding") == "gzip"):
            self._decompressor = GzipDecompressor()
        if self.headers.get("Transfer-Encoding") == "chunked":
            self.chunks = []
            self.request.stream.read_until(b("\r\n"), self._on_chunk_length)
        elif content_length is not None:
            self.request.stream.read_bytes(content_length, self._on_body)
        else:
            self.request.stream.read_until_close(self._on_body)

    def _on_body(self, data):
        if self._timeout is not None:
            self.io_loop.remove_timeout(self._timeout)
            self._timeout = None
        original_request = getattr(self.request, "original_request",
                                   self.request)
        if (self.request.follow_redirects and
            self.request.max_redirects > 0 and
            self.code in (301, 302, 303, 307)):
            new_request = copy.copy(self.request)
            new_request.url = urlparse.urljoin(self.request.url,
                                               self.headers["Location"])
            new_request.max_redirects -= 1
            del new_request.headers["Host"]
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
            # Client SHOULD make a GET request after a 303.
            # According to the spec, 302 should be followed by the same
            # method as the original request, but in practice browsers
            # treat 302 the same as 303, and many servers use 302 for
            # compatibility with pre-HTTP/1.1 user agents which don't
            # understand the 303 status.
            if self.code in (302, 303):
                new_request.method = "GET"
                new_request.body = None
                for h in ["Content-Length", "Content-Type",
                          "Content-Encoding", "Transfer-Encoding"]:
                    try:
                        del self.request.headers[h]
                    except KeyError:
                        pass
            new_request.original_request = original_request
            final_callback = self.final_callback
            self.final_callback = None
            self._release()
            self.client.fetch(new_request, final_callback)
            self.request.stream.close()
            return
        if self._decompressor:
            data = (self._decompressor.decompress(data) +
                    self._decompressor.flush())
        if self.request.streaming_callback:
            if self.chunks is None:
                # if chunks is not None, we already called streaming_callback
                # in _on_chunk_data
                self.request.streaming_callback(data)
            buffer = BytesIO()
        else:
            buffer = BytesIO(data)  # TODO: don't require one big string?
        response = HTTPResponse(original_request,
                                self.code, reason=self.reason,
                                headers=self.headers,
                                request_time=self.io_loop.time() - self.start_time,
                                buffer=buffer,
                                effective_url=self.request.url)
        self._run_callback(response)
        self.request.stream.close()

    def _on_chunk_length(self, data):
        # TODO: "chunk extensions" http://tools.ietf.org/html/rfc2616#section-3.6.1
        length = int(data.strip(), 16)
        if length == 0:
            if self._decompressor is not None:
                tail = self._decompressor.flush()
                if tail:
                    # I believe the tail will always be empty (i.e.
                    # decompress will return all it can).  The purpose
                    # of the flush call is to detect errors such
                    # as truncated input.  But in case it ever returns
                    # anything, treat it as an extra chunk
                    if self.request.streaming_callback is not None:
                        self.request.streaming_callback(tail)
                    else:
                        self.chunks.append(tail)
                # all the data has been decompressed, so we don't need to
                # decompress again in _on_body
                self._decompressor = None
            self._on_body(b('').join(self.chunks))
        else:
            self.request.stream.read_bytes(length + 2,  # chunk ends with \r\n
                              self._on_chunk_data)

    def _on_chunk_data(self, data):
        assert data[-2:] == b("\r\n")
        chunk = data[:-2]
        if self._decompressor:
            chunk = self._decompressor.decompress(chunk)
        if self.request.streaming_callback is not None:
            self.request.streaming_callback(chunk)
        else:
            self.chunks.append(chunk)
        self.request.stream.read_until(b("\r\n"), self._on_chunk_length)


# match_hostname was added to the standard library ssl module in python 3.2.
# The following code was backported for older releases and copied from
# https://bitbucket.org/brandon/backports.ssl_match_hostname
class CertificateError(ValueError):
    pass


def _dnsname_to_pat(dn):
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)


def match_hostname(cert, hostname):
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 rules
    are mostly followed, but IP addresses are not accepted for *hostname*.

    CertificateError is raised on failure. On success, the function
    returns nothing.
    """
    if not cert:
        raise ValueError("empty or no certificate")
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'DNS':
            if _dnsname_to_pat(value).match(hostname):
                return
            dnsnames.append(value)
    if not san:
        # The subject is only checked when subjectAltName is empty
        for sub in cert.get('subject', ()):
            for key, value in sub:
                # XXX according to RFC 2818, the most specific Common Name
                # must be used.
                if key == 'commonName':
                    if _dnsname_to_pat(value).match(hostname):
                        return
                    dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError("hostname %r "
            "doesn't match either of %s"
            % (hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname %r "
            "doesn't match %r"
            % (hostname, dnsnames[0]))
    else:
        raise CertificateError("no appropriate commonName or "
            "subjectAltName fields were found")

if __name__ == "__main__":
    AsyncHTTPClient.configure(SimpleAsyncHTTPClient)
    main()
