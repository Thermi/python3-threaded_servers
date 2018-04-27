#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2009-2016  Xyne
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# (version 2) as published by the Free Software Foundation.
#
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import argparse
import calendar
import errno
import hashlib
import http.server
import itertools
import json
import logging
import mimetypes
import os
import random
import socket
import socketserver
import ssl
import sys
import tarfile
import threading
import time
import urllib.parse

from .common import (
  add_common_argparse_groups,
  configure_logging,
  DAEMON_THREADS,
  DEFAULT_CHUNK_FACTOR,
  DEFAULT_CHUNK_SIZE,
  format_size,
  format_time,
  format_uri,
  get_all_interfaces,
  get_ip_addresses,
  get_name,
  RFC_2822_TIME_FORMAT,
  run,
  ServerError,
  unbound_address,
  VERSION
)

from .Base import BaseServer

NAME = get_name(__file__, __package__)
VERSION_STRING = '{}/{}'.format(NAME, VERSION)
UTF8 = 'UTF-8'
TAR_COMPRESSIONS = ('none', 'gz', 'bz2', 'xz')

############################## Generic Functions ###############################


def parse_range_header(header, size=None):
  '''
  Parse HTTP "Range" headers. Range headers may take the form "a-b,c-d,e-f".

  This function assumed that the range headers are well-formed, i.e. that there
  are no extra spaces, invalid offsets, or extra characters.
  '''
  try:
    unit, ranges = header.split('=', 1)
  except ValueError:
    raise ValueError('Range header does not contain "="')

  if unit != 'bytes':
    raise ValueError('unrecognized Range unit: {}'.format(unit))

  for r in ranges.split(','):
    start, end = r.split('-')
    if start:
      try:
        start = int(start)
      except ValueError:
        raise ValueError('invalid start in Range header: {}'.format(start))
    else:
      start = 0
    if end:
      try:
        end = int(end) + 1
      except ValueError:
        raise ValueError('invalid end in Range header: {}'.format(end))
    else:
      end = size
    yield start, end



def get_valid_ranges(ranges, size):
  for s, e in ranges:
    s = max(0, s)
    e = min(size, e)
    if s >= e \
    or e < 0 \
    or s >= size:
      continue
    yield s, e



def format_content_range(ranges, size):
  '''
  Format "Content-Range" headers.
  '''
  return 'bytes {}/{:d}'.format(
    ','.join('{:d}-{:d}'.format(s,e-1) for s,e in ranges),
    size,
  )



def get_length_from_ranges(ranges):
  '''
  Calculate the total content length from a list of ranges.
  '''
  n = 0
  for s, e in ranges:
    n += e - s
  return n



def get_digest_hash(xs):
  h = hashlib.md5()
  h.update(':'.join(xs).encode(UTF8))
  return h.hexdigest()



def get_tar_mtime(dpath):
  '''
  Get the last modification time of a the last modified path in a directory.
  '''
  mtime = 0
  for root, dirs, files in os.walk(dpath):
    for entry in itertools.chain(dirs, files):
      path = os.path.join(root, entry)
      mtime = max(mtime, os.path.getmtime(path))
  return mtime



def add_tar_extension(path, compression=None):
  '''
  Add an appropriate tar extension to the given path.
  '''
  if not compression or compression == 'none':
    return '{}.tar'.format(path)
  else:
    return '{}.tar.{}'.format(path, compression)



def get_tar_mimetype(compression=None):
  if not compression or compression == 'none':
    return 'application/x-tar'
  if compression == 'gz':
    mimetype = 'gzip'
  elif compression == 'bz2':
    mimetype = 'bzip'
  elif compression == 'xz':
    mimetype = 'xz'
  else:
    return 'application/octet-stream'
  return 'application/x-{}'.format(mimetype)



################################# ChunkWriter ##################################
class ChunkWriter(object):
  '''
  File object wrapper to transfer HTTP chunks. Only the write method is modified.
  '''
  def __init__(self, fileobj):
    self.fileobj = fileobj

  def write(self, data, *args, **kwargs):
    n = len(data)
    self.fileobj.write('{:X}\r\n'.format(n).encode(UTF8), *args, **kwargs)
    self.fileobj.write(data, *args, **kwargs)
    self.fileobj.write(b'\r\n', *args, **kwargs)

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    # Write empty chunk to indicate end of transfer.
    self.fileobj.write(b'0\r\n\r\n')

#   def __getattr__(self, *args, **kwargs):
#     return getattr(self.fileobj, *args, **kwargs)
#
#   def __setattr__(self, *args, **kwargs):
#     return setattr(self.fileobj, *args, **kwargs)
#
#   def __delattr__(self, *args, **kwargs):
#     return delattr(self.fileobj, *args, **kwargs)



################################# HTTPSServer ##################################‎
class HTTPSServer(
  BaseServer,
  http.server.HTTPServer
):
  '''
  Threaded HTTP(S) Server.
  '''
  # After this number of requests the client must re-auth.
  # The maximum value is 0xffffffff
  NC_LIMIT = 0xffffffff

  # The number of seconds after which the client must re-auth if no requests
  # were made.
  OPAQUE_TIMEOUT = 3600

  def __init__(
    self,
    server_address,
    handler,
    options,
    nc_limit=None,
    opaque_timeout=None,
    *args,
    **kwargs
  ):
    super().__init__(options)
    if options.ipv6:
      self.address_family = socket.AF_INET6

    if not unbound_address(server_address[0]):
      for ip in get_ip_addresses(server_address[0]):
        server_address = (ip, server_address[1])
        break

    http.server.HTTPServer.__init__(self, server_address, handler, *args, **kwargs)
    self.handler = handler

    self.lock = threading.Lock()

    self.authorized = get_authorized(options)

    if options.ssl:
      self.ssl_parameters = get_ssl_parameters(options)
    else:
      self.ssl_parameters = None
    try:
      self.ssl_parameters['server_side'] = True
    except TypeError:
      pass

    if options.cert_required:
      self.ssl_parameters['cert_reqs'] = ssl.CERT_REQUIRED
      if not self.ssl_parameters['ca_certs']:
        self.ssl_parameters['ca_certs'] = self.ssl_parameters['certfile']


    self.opaques = dict()

    if nc_limit is None:
      self.nc_limit = self.NC_LIMIT
    else:
      self.nc_limit = nc_limit

    if opaque_timeout is None:
      self.opaque_timeout = self.OPAQUE_TIMEOUT
    else:
      self.opaque_timeout = opaque_timeout



  def delete_opaque(self, opaque):
    with self.lock:
      try:
        del self.opaques[opaque]
      except KeyError:
        pass



  def get_request(self):
    '''
    Overridden method for SSL support.
    '''
    conn, addr = self.socket.accept()
    if self.ssl_parameters:
      conn = ssl.wrap_socket(conn, **self.ssl_parameters)
    return conn, addr



  def finish_request(self, request, client_address):
    try:
      http.server.HTTPServer.finish_request(self, request, client_address)
    except ssl.SSLError as e:
      self.log_error('SSLError: {}'.format(e.reason))
    except (BrokenPipeError, ConnectionResetError) as e: #Python3
#     except OSError as e: #Python2
#       if e.errno in (errno.EPIPE, errno.ECONNRESET): #Python2
        self.log_error('{}'.format(e))
#       else: #Python2
#         raise e #Python2



  def clean_house(self):
    # Clean up old opaque values.
    with self.lock:
      for k in list(self.opaques.keys()):
        try:
          if time.time() - self.opaques[k]['time'] > self.opaque_timeout:
            del self.opaques[k]
        except KeyError:
          continue



  def get_scheme(self):
    if self.options.ssl:
      return 'https'
    else:
      return 'http'



  def get_server_uris(self, path='/'):
    '''
    Generator over all local URIs via which the server is accessible.
    '''
    scheme = self.get_scheme()
    port = self.options.port
    address = self.options.address
    if address:
      ips = (address,)
    else:
      ips = (ip for _, ip in get_all_interfaces())
    for ip in ips:
      yield format_uri(scheme, ip, port, path)


############################ BaseHTTPSRequestHandler ############################

class BaseHTTPSRequestHandler(http.server.BaseHTTPRequestHandler, object):
  '''
  HTTP(S) request handler with support for HTTP authorization.
  '''
  # The nonce and opaque lengths.
  NONCE_LENGTH = 32

  # Override protocol version.
  protocol_version = 'HTTP/1.1'

  # Override version string method.
  def version_string(self):
    return VERSION_STRING

  # Overrite the log timestamp format.
  def log_date_time_string(self):
    return format_time()

  # Override to use the logging module.
  def log_message(self, fmt, *args):
    if args:
      string = fmt % args
    else:
      string = fmt
    msg = '{} {}'.format(self.client_address[0], string)
    logging.info(msg)

  # Override to use the logging module.
  def log_error(self, fmt, *args):
    if args:
      string = fmt % args
    else:
      string = fmt
    msg = '{} {}'.format(self.client_address[0], string)
    logging.error(msg)



  def __init__(self, *args, **kwargs):
    http.server.BaseHTTPRequestHandler.__init__(self, *args, **kwargs)




  def create_nonce(self):
    '''
    Create a nonce value.
    '''
    nonce_max = 1 << (self.NONCE_LENGTH * 4) - 1
    return '{:0{width}x}'.format(
      random.randint(0, nonce_max),
      width=self.NONCE_LENGTH
    )



  def get_nonce(self, opaque, nc):
    '''
    Get a nonce value from a given opaque if the nonce count (nc) matches.
    '''

    try:
      if self.server.opaques[opaque]['nc'] != nc:
        self.server.delete_opaque(opaque)
        return None
      else:
        count = int(nc,16) + 1
        if count > self.server.nc_limit:
          self.server.delete_opaque(opaque)
          return None
        else:
          with self.server.lock:
            self.server.opaques[opaque]['nc'] = '{:08x}'.format(count)
            self.server.opaques[opaque]['time'] = time.time()
            return self.server.opaques[opaque]['nonce']
    except KeyError as e:
      return None



  def get_realm(self):
    '''
    Return the realm. Can be overridden in subclasses.
    '''
    return self.address_string()



  def reject_unauthenticated_request(self):
    '''
    Reject an unauthenticated request.
    '''
    nonce =  self.create_nonce()
    opaque = self.create_nonce()
    with self.server.lock:
      self.server.opaques[opaque] = {
        'nonce': nonce,
        'time': time.time(),
        'nc': '{:08x}'.format(1),
      }
    self.send_response(401)
    self.send_header('Content-Length', 0)
    self.send_header(
      'WWW-Authenticate',
      'Digest realm="{realm}",qop="auth",nonce="{nonce}",opaque="{opaque}"'.format(
        realm=self.get_realm(),
        nonce=nonce,
        opaque=opaque,
      )
    )
    self.send_header('Connection', 'close')
    self.end_headers()




  def authenticate(self, method):
    '''
    Attempt to authenticate HTTP requests and reject those that fail.

    The specification only supports GET and POST methods. GET should be used for
    HEAD requests.

    The return value indicates if the authentication succeeded.
    '''
    authed = False
    if self.server.authorized is not None:
      if 'Authorization' in self.headers:
        header = self.headers['Authorization'].strip()
        typ, fields = header.split(' ', 1)
        if typ == 'Digest':
          authorization = dict()
          for field in fields.split(','):
            field = field.strip()
            name, value = field.split('=', 1)
            name = name.rstrip()
            value = value.lstrip().strip('"')
            authorization[name] = value
          try:
            nonce = self.get_nonce(authorization['opaque'], authorization['nc'])
            if nonce is not None:
              for username, password in self.server.authorized.items():
                a = get_digest_hash((username, self.get_realm(), password))
#                 if directive == 'MD5-sess':
#                   a = get_digest_hash((a, authorization['nonce'], authorization['cnonce']))
                try:
                  if authorization['qop'] == 'auth-int':
                    entity_body = self.rfile.read()
                    md5_entity_body = get_digest_hash((entity_body,))
                    b = get_digest_hash((method, self.path, md5_entity_body))
                  elif authorization['qop'] == 'auth':
                    b = get_digest_hash((method, self.path))
                  else:
                    self.log_error(
                      'unsupported qop value: {}'.format(authorization['qop'])
                    )
                    self.send_error(400)
                    return False
                  response = get_digest_hash((
                    a,
                    nonce,
                    authorization['nc'],
                    authorization['cnonce'],
                    authorization['qop'],
                    b
                  ))
                except KeyError:
                  b = get_digest_hash((method, self.path))
                  response = get_digest_hash((
                    a,
                    nonce,
                    b
                  ))
                if response == authorization['response']:
                  authed = True
                  self.authorization = authorization
                  break
          except KeyError as e:
            self.log_error(
              'missing key in client authentication: {}'.format(e)
            )
        else:
          self.log_error(
            'unsupported HTTP authorization method: {}'.format(typ)
          )
    else:
      authed = True

    if not authed:
      self.reject_unauthenticated_request()

    return authed





  def transfer_utf8_content(
    self,
    content,
    content_type='application/octet-stream',
    include_body=True,
    status_code=200,
    encode=True,
    location=None,
    close=False,
  ):
    '''
    Convenience method for transferring UTF-8 encoded content.
    '''

    if include_body \
    and status_code >= 200 \
    and status_code not in (204, 205, 304):
      include_body = (self.command != 'HEAD')
    else:
      content = None
      include_body = False


    if content is None:
      content_length = 0
    else:
      if encode:
        try:
          content = content.encode(UTF8)
        except UnicodeDecodeError:
          pass
      content_length = len(content)

    self.send_response(status_code)
    self.send_header('Content-Type', '{}; charset={}'.format(content_type, UTF8))
    self.send_header('Content-Length', content_length)
    if location is not None:
      self.send_header('Location', location)
    if close:
      self.send_header('Connection', 'close')
    self.end_headers()

    if content is not None:
      self.wfile.write(content)



  def transfer_html(
    self, html, include_body=True, status_code=200, close=True
  ):
    '''
    Transfer a UTF-8-encoded HTML page.
    '''
    return self.transfer_utf8_content(
      html,
      content_type='text/html',
      include_body=include_body,
      status_code=status_code,
      close=close,
    )



  def transfer_plaintext(
    self, text, include_body=True, status_code=200, close=True
  ):
    '''
    Transfer a UTF-8-encoded plaintext page.
    '''
    return self.transfer_utf8_content(
      text,
      content_type='text/plain',
      include_body=include_body,
      status_code=status_code,
      close=close,
    )



  def transfer_json(
    self, obj, include_body=True, status_code=200, close=True, *args, **kwargs
  ):
    '''
    Transfer UTF-8-encoded JSON data.
    '''
    text = json.dumps(obj, *args, **kwargs)
    return self.transfer_utf8_content(
      text,
      content_type='application/json',
      include_body=include_body,
      status_code=status_code,
      close=close,
    )




  def redirect(self, location='/', status_code=303, message=None, close=True):
    '''
    Redirect to a local server path.
    '''
    if message is None:
      message = location

    return self.transfer_utf8_content(
      message,
      content_type='text/plain',
      include_body=True,
      status_code=status_code,
      encode=True,
      location=location,
      close=close,
    )



  def transfer_directory(
    self,
    dpaths,
    name,
    *args,
    include_body=True,
    compression=None,
    hide_path=None,
    **kwargs
  ):
    '''
    Transfer a directory by recursivingly adding its contents to a tar file.

    dpaths:
      The directories to transfer.

    include_body:
      If True, transfer the content, else only transfer the header.

    compression:
      A compression type supported by Python's tarfile module.

    All other positional and keyword arguments are passed to tarfile.open.
    '''
    if not compression or compression == 'none':
      compression = ''
    elif compression not in TAR_COMPRESSIONS:
      self.log_error('unsupported tar compression type: {}'.format(compression))
      self.send_error(501)
      return
    archive_name = add_tar_extension(name, compression=compression)
    mimetype = get_tar_mimetype(compression=compression)

    mtime = max(get_tar_mtime(d) for d in dpaths)
    last_modified = self.date_time_string(mtime)

    code = 200
    if 'If-Modified-Since' in self.headers:
      if_modifed_since = time.strptime(
        self.headers['If-Modified-Since'], RFC_2822_TIME_FORMAT
      )
      if mtime <= calendar.timegm(if_modifed_since):
        code = 304
        include_body = False

    self.send_response(code)
    self.send_header('Content-Type', mimetype)
    self.send_header('Last-Modified', last_modified)
    self.send_header('Accept-Ranges', 'none')
    self.send_header('Transfer-Encoding', 'chunked')
    # http://stackoverflow.com/questions/93551/how-to-encode-the-filename-parameter-of-content-disposition-header-in-http
    # http://greenbytes.de/tech/webdav/rfc5987.html
    self.send_header('Content-Disposition', 'inline; filename*={}\'\'{}'.format(
      UTF8,
      urllib.parse.quote(archive_name)
      ))
    self.end_headers()

    def tarfilter(ti):
      if hide_path is not None and hide_path(ti.name):
        return None
      ti.uid = ti.gid = 0
      ti.uname = ti.gname = 'nobody'
      return ti

    if include_body:
      with ChunkWriter(self.wfile) as cw:
        with tarfile.open(
          *args,
          mode='w|'.format(compression),
          fileobj=cw,
          dereference=True,
          **kwargs
        ) as t:
          for dpath in dpaths:
            t.add(dpath, arcname=name, filter=tarfilter)



  def transfer_file(
    self,
    fpath,
    include_body=True,
    chunk_size=None,
  ):
    '''
    Transfer the contents of a file, with support for the Range header.
    '''
    size = os.path.getsize(fpath)
    mimetype, encoding = mimetypes.guess_type(fpath)
    mtime = os.path.getmtime(fpath)
    last_modified = self.date_time_string(mtime) # RFC 2822
    if not mimetype:
      mimetype = 'application/octet-stream'

    if 'Range' in self.headers:
      try:
        ranges = list(
          get_valid_ranges(
            parse_range_header(self.headers['Range'], size=size),
            size
          )
        )
        code = 206
      except ValueError:
        self.send_error(400)
        return
      if not ranges:
        self.send_error(416) # Requested Range Not Satisfiable
        return
    else:
      ranges = list(((0, size),))
      code = 200

    if len(ranges) > 1:
      mimetype = 'multipart/byteranges'

    if 'If-Modified-Since' in self.headers:
      if_modifed_since = time.strptime(
        self.headers['If-Modified-Since'], RFC_2822_TIME_FORMAT
      )
      if mtime <= calendar.timegm(if_modifed_since):
        code = 304
        include_body = False

    self.send_response(code)
    self.send_header('Content-Type', mimetype)
    self.send_header('Last-Modified', last_modified)
    self.send_header('Accept-Ranges', 'bytes')

    if include_body:
      self.send_header('Content-Length', get_length_from_ranges(ranges))
      if encoding:
        self.send_header('Content-Encoding', encoding)
      self.send_header('Content-Range', format_content_range(ranges, size))
      self.end_headers()

      # This does not affect "include_body" above because a HEAD request should
      # return the same metadata as a GET request.
      if self.command != 'HEAD':
        try:
          with open(fpath, 'rb') as f:
            if chunk_size is None:
              chunk_size = getattr(f, '_CHUNK_SIZE', DEFAULT_CHUNK_SIZE)
            chunk_size *= DEFAULT_CHUNK_FACTOR

            ranges_sent = list()
            for start, end in ranges:
              f.seek(start, os.SEEK_SET)
              remaining = end - start
              bytes_sent = 0
              while remaining > 0:
                chunk = f.read(min(remaining, chunk_size))
                if chunk:
                  bytes = self.wfile.write(chunk)
                  bytes_sent += bytes
#                   bytes = len(chunk) #Python2
                  remaining -= bytes
                  if bytes != len(chunk): #Python3
                    break #Python3
                else:
                  self.log_error('local EOF error [{}]'.format(fpath))
              ranges_sent.append((start, end, bytes_sent))

          # Report file transfer data.
          total_bytes_sent = 0
          number_of_ranges = len(ranges)
          report_total = number_of_ranges > 1

          for start, end, bytes_sent in ranges_sent:
            range_size = end - start
            total_bytes_sent += bytes_sent

            if range_size == size:
              self.log_message(
                '{} / {} transferred [{}]'.format(
                  format_size(bytes_sent),
                  format_size(size),
                  fpath
                )
              )
            else:
              self.log_message(
                '{} / {} transferred [range {:d}-{:d}/{:d} of {}]'.format(
                  format_size(bytes_sent),
                  format_size(range_size),
                  start,
                  end,
                  size,
                  fpath
                )
              )

          if report_total:
            self.log_message(
              '{} / {} transferred in {:d} ranges [{}]'.format(
                format_size(total_bytes_sent),
                size,
                number_of_ranges,
                fpath
              )
            )


        except (BrokenPipeError, ConnectionResetError) as e: #Python3
#         except OSError as e: #Python2
#           if e.errno in (errno.EPIPE, errno.ECONNRESET): #Python2
            user_agent = self.headers['User-Agent']
            if user_agent is None:
              user_agent = ''
            else:
              user_agent = ' [{}]'.format(user_agent)
            self.log_error('connection closed by client{}'.format(user_agent))
#           else: #Python2
#             raise e #Python2
    else:
      self.send_header('Content-Length', '0')
      self.end_headers()



  def do_GET(self):
    if self.authenticate('GET'):
      self.server.clean_house()
      self.do_authenticated_GET()

  def do_HEAD(self):
    if self.authenticate('GET'):
      self.server.clean_house()
      self.do_authenticated_HEAD()

  def do_POST(self):
    if self.authenticate('POST'):
      self.server.clean_house()
      self.do_authenticated_POST()
    return True




########################## SimpleHTTPSRequestHandler ###########################
class SimpleHTTPSRequestHandler(
  BaseHTTPSRequestHandler,
  http.server.SimpleHTTPRequestHandler,
):
  '''
  Subclass of http.server.SimpleHTTPRequestHandler.
  '''

  def __init__(self, *args, **kwargs):
    http.server.SimpleHTTPRequestHandler.__init__(self, *args, **kwargs)

  def do_authenticated_GET(self):
    http.server.SimpleHTTPRequestHandler.do_GET(self)

  def do_authenticated_HEAD(self):
    http.server.SimpleHTTPRequestHandler.do_HEAD(self)

  def do_authenticated_POST(self):
    http.server.SimpleHTTPRequestHandler.do_POST(self)




########################## SimpleHTTPSRequestHandler ###########################
class CGIHTTPSRequestHandler(
  BaseHTTPSRequestHandler,
  http.server.CGIHTTPRequestHandler,
):
  '''
  Subclass of http.server.SimpleHTTPRequestHandler.
  '''

  def __init__(self, *args, **kwargs):
    http.server.CGIHTTPRequestHandler.__init__(self, *args, **kwargs)

  def do_authenticated_GET(self):
    http.server.CGIHTTPRequestHandler.do_GET(self)

  def do_authenticated_HEAD(self):
    http.server.CGIHTTPRequestHandler.do_HEAD(self)

  def do_authenticated_POST(self):
    http.server.CGIHTTPRequestHandler.do_POST(self)





############################### Argument Parsing ###############################
def add_HTTPS_argparse_groups(parser):

  # HTTP Authentication
  auth_options = parser.add_argument_group(
    title="HTTP Authentication",
    description="HTTP digest authentication via a username and password."
  )
  auth_options.add_argument(
    "--auth", nargs=2, metavar='<string>', action='append', default=[],
    help="HTTP digest username and password. Multiple pairs may be passed.",
  )
  auth_options.add_argument(
    "--authfile", metavar='<filepath>',
    help="The path to a file containing alternating lines of usernames and passwords.",
  )

  # SSL
  ssl_options = parser.add_argument_group(
    title="SSL (HTTPS)",
    description='Options for wrapping sockets in SSL for encrypted connections. Simply enabling SSL does not guarantee a secure connection and it is the user\'s responsibility to check that the implementation is correct and secure and that the server is properly configured. You can find information about generating self-signed certificates in the OpenSSL FAQ: http://www.openssl.org/support/faq.html',
  )
  ssl_options.add_argument(
    "--ssl", action="store_true",
  help="Enable SSL (HTTPS).",
  )
  ssl_options.add_argument(
    "--certfile", metavar="<filepath>",
    help="The path to the server's certificate.",
  )
  ssl_options.add_argument(
    "--keyfile", metavar="<filepath>",
    help="The path to the server's key.",
  )
  ssl_options.add_argument(
    "--req-cert", dest='cert_required', action="store_true",
    help="Require a certificate from the client.",
  )
  ssl_options.add_argument(
    "--ca-certs", metavar="<filepath>",
    help="Set the path to a file containing concatenated CA certificates for verifying the client certificate. This defaults to the server's own certificate."
  )

  return parser


def get_authorized(args):
  '''
  Collect the list of username-password pairs for HTTP digest authentication.
  '''
  authorized = dict((u,p) for u,p in args.auth)
  if args.authfile:
    with open(args.authfile, 'r') as f:
      for username in f:
        password = f.readline()
        if not password:
          break
        authorized[username] = password
  if authorized:
    return authorized
  else:
    return None



def get_ssl_parameters(args):
  '''
  Return a dictionary of SSL parameters.
  '''
  return {
    'ca_certs' : args.ca_certs,
    'certfile' : args.certfile,
    'keyfile' : args.keyfile,
  }



##################################### Main #####################################
def main(args=None):
  parser = argparse.ArgumentParser(
    description='Run a basic HTTP(S) server with HTTP digest authentication support.',
  )
  parser = add_common_argparse_groups(parser)
  parser = add_HTTPS_argparse_groups(parser)
  args = parser.parse_args(args)
  address = (args.address, args.port)
  handler = SimpleHTTPSRequestHandler
  server = HTTPSServer(
    address,
    handler,
    args,
  )
  server.serve_forever()


if __name__ == '__main__':
  configure_logging()
  run(main)