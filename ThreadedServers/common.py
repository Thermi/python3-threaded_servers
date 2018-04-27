#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2009-2013  Xyne
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

import array
import errno
import fcntl
import ipaddress
import logging
import os
import posixpath
import signal
import socket
import struct
import sys
import threading
import time
import urllib.parse

VERSION = '2013.05.12'
AUTHOR = 'Xyne'
HOMEPAGE = 'http://xyne.archlinux.ca/projects/quickserve'

# True means that all threads are killed when the main thread exits.
DAEMON_THREADS = True

# Number of times to attempt interrupting with exit before sending SIGKILL.
SIGINTS_BEFORE_SIGKILL = 1
SIGINTS_RECEIVED = 0

DEFAULT_CHUNK_SIZE = 0x1000
DEFAULT_CHUNK_FACTOR = 0x10 #0x80
RFC_2822_TIME_FORMAT = '%a, %d %b %Y %H:%M:%S %Z'
ISO_8601_TIME_FORMAT = '%Y-%m-%d %H:%M:%S %Z'



################################ Generic Error #################################

class ServerError(Exception):
  pass


############################ Path And URI Functions ############################
# These should make the various URI path manipulations OS-agnostic.


def serverpath_from_uripath(uripath):
  '''
  The path is assumed to have been extracted with urllib.parse.urlsplit
  '''
  path = posixpath.normpath(urllib.parse.unquote(uripath))
  while path[:3] == '../':
    path = path[3:]
  return path


# Compare http.server's "translate_path"
def serverpath_to_localpath(path, start=None):
  path = serverpath_from_uripath(path)
  words = [w for w in path.split('/') if w]
  if start is None:
    path = os.getcwd()
  else:
    path = start
  for word in words:
    drive, word = os.path.splitdrive(word)
    head, word = os.path.split(word)
    if word in (os.curdir, os.pardir):
      continue
    path = os.path.join(path, word)
  return path




def iterate_qs(qs):
  '''
  Iterate values from urllib.parse.parse_qs-parsed query strings.
  '''
  for q, vs in qs.items():
    for v in vs:
      yield q, v



def unparse_qs(qs):
  '''
  Recreate a query string, i.e. reverse urllib.parse.parse_qs.
  '''
  return '&'.join(
    '{}={}'.format(
      urllib.parse.quote_plus(q),
      urllib.parse.quote_plus(v)
    )for q, v in iterate_qs(qs)
  )



def replace_uri_host_and_get_port(uri, host='ungabunga', scheme='http', port=80):
  '''
  Replace the network location in the given URI.
  '''
  uri_data = urllib.parse.urlsplit(uri)

  if not uri_data.scheme:
    scheme = scheme
  else:
    scheme = uri_data.scheme

  if not uri_data.port:
    port = port
  else:
    port = uri_data.port

  return format_uri(scheme, host, port, uri_data.path), port


#################################### System ####################################

# TODO
# Check if there is a better way to do this.
def get_local_ipv6_addresses():
  try:
    with open('/proc/net/if_inet6', 'r') as f:
      for line in f:
        addr, _, _, _, _, iface = line.split()
        yield iface, ipaddress.IPv6Address(int(addr, 0x10))
  except FileNotFoundError:
    pass


# # TODO
# # Find a better way to do this.
# def get_all_addresses_from_address(address):
#   '''
#   Return all addresses associated with an interface. This will determine the
#   host name from the address with socket.gethostbyaddr() and then get all of the
#   host's addresses with socketgetaddrinfo(). The returned addresses are then
#   filtered to remove duplicates and return the addresses associated with the
#   same interface as the input address.
#   '''
#   # Use the hostname to get both IPv4 and IPv6 addresses. Using only the address
#   # limits the result to that address.
#   hostname = socket.gethostbyaddr(str(address))[0]
#   ipv4 = dict()
#   ipv6 = dict()
#   for info in socket.getaddrinfo(hostname, None):
#     print(info)
#     addr = info[4][0]
#     try:
#       addr, iface = addr.split('%', 1)
#     except ValueError:
#       iface = None
#
#     addr = ipaddress.ip_address(addr)
#     if isinstance(addr, ipaddress.IPv6Address):
#       ipv6[addr] = iface
#     else:
#       ipv4[addr] = iface
#
#   # TODO
#   # Handle exceptions.
#   try:
#     interface = ipv4[address]
#   except KeyError:
#     interface = ipv6[address]
#
#   yield from sorted(addr for (addr, iface) in ipv4.items() if iface == interface)
#   yield from sorted(addr for (addr, iface) in ipv6.items() if iface == interface)


# TODO
# Handle IPv6 addresses.
def get_ip_addresses(ifname):
  '''
  Return the IP address of an interface (if it has one).
  '''
  SIOCGIFADDR = 0x8915
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
      address = ipaddress.ip_address(
        socket.inet_ntoa(
          fcntl.ioctl(
            sock.fileno(),
            SIOCGIFADDR,
            struct.pack(b'256s', ifname[:15].encode('UTF-8'))
          )[20:24]
        )
      )
      yield address
#       yield from get_all_addresses_from_address(address)
  except OSError as e:
    if e.errno in (errno.ENODEV, errno.EADDRNOTAVAIL):
      pass
    else:
      raise e
  for iface, address in get_local_ipv6_addresses():
    if iface == ifname:
      yield address




# TODO
# Handle IPv6 addresses.
def get_all_interfaces(n_max=128):
  '''
  Generator to iterate over 2-tuples of names and IP address for all interfaces.
  '''
  SIOCGIFCONF = 0x8912
  buffer_size = 32 * n_max
  buf = array.array('B', b'\0' * buffer_size)
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    filled_bytes = struct.unpack(
      'iL',
      fcntl.ioctl(
        sock.fileno(),
        SIOCGIFCONF,
        struct.pack('iL', buffer_size, buf.buffer_info()[0])
      )
    )[0]
  bytestring = buf.tostring()
  for i in range(0, filled_bytes, 40):
    interface = bytestring[i:i+16].split(b'\0', 1)[0].decode()
    ip = ipaddress.ip_address(socket.inet_ntoa(bytestring[i+20:i+24]))
    yield interface, ip
#     for addr in get_all_addresses_from_address(ip):
#       yield interface, addr
  for interface, ip in get_local_ipv6_addresses():
    yield interface, ip



def replace_interfaces_with_ips(args=None):
  '''
  Replace interface names with IP addresses. Other arguments are unchanged. If
  args is None, return all interface IPs.
  '''
  if args is None:
    return (ip for (_, ip) in get_all_interfaces())
  else:
    interfaces = dict(get_all_interfaces())
    return (interfaces.get(arg, arg) for arg in args)



def get_name(f, p):
  '''Call with __file__ and __package__.'''
  return os.path.splitext(f[f.rindex(p):])[0].replace(os.sep, '.')


def unbound_address(ip):
  return ip in ('', '0.0.0.0', None)



#################################### Format ####################################
def format_size(size):
  '''Format bytes for humans.'''
  if size < 0x400:
    return '{:d} B'.format(size)
  else:
    size = float(size) / 0x400
  for prefix in ('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB'):
    if size < 0x400:
      return '{:0.02f} {}'.format(size, prefix)
    else:
      size /= 0x400
  return '{:0.02f} YiB'.format(size)



def format_time(t=None, UTC=True):
  '''Format UNIX time to a ISO 8601 format.'''
  if UTC:
    t = time.gmtime(t)
  else:
    t = time.localtime(t)
  return time.strftime(ISO_8601_TIME_FORMAT, t)



def format_seconds(s):
  '''Format seconds for inferior humans.'''
  string = ''
  for base, char in (
    (60, 's'),
    (60, 'm'),
    (24, 'h')
  ):
    s, r = divmod(s, base)
    if s == 0:
      return '{:d}{}{}'.format(r, char, string)
    elif r != 0:
      string += '{:02d}{}{}'.format(r, char, string)
  else:
    return '{:d}d{}'.format(s, string)



def format_uri(scheme, host, port, path):
  '''
  Format a URI.
  '''
  return '{}://{}:{:d}{}'.format(scheme, host, port, path)



##################################### Main #####################################

def add_common_argparse_groups(parser, port=8000):
  listening_options = parser.add_argument_group(
    title="Server Address and Port",
    description="Configure the server's listening address and port."
  )
  listening_options.add_argument(
    "-a", "--address", metavar='<interface|address>', default='',
    help='Bind the server to this address. By default the server will listen on all interfaces.',
  )
  listening_options.add_argument(
    "-p", "--port", type=int, metavar='<port>', default=port,
    help='Set the server port (default: %(default)s)',
  )
  listening_options.add_argument(
    "--ipv6", action='store_true',
    help='Use IPv6.',
  )
  return parser



def kill_myself(signum, frame):
  os.kill(os.getpid(), signal.SIGKILL)



def handle_interrupt(signum, frame):
  '''
  Attempt to exit on SIGINT (ctrl+c). Bind the signal handler to kill_myself()
  for subsequent calls.
  '''
  global SIGINTS_BEFORE_SIGKILL
  global SIGINTS_RECEIVED

  if SIGINTS_RECEIVED >= SIGINTS_BEFORE_SIGKILL:
    sys.stderr.write('\nThe next SIGINT will send a SIGKILL.\n')
    signal.signal(signal.SIGINT, kill_myself)

  elif SIGINTS_RECEIVED >= 1:
    sys.stderr.write(
      '\n{:d} SIGINTS remaining before SIGKILL.\n'.format(SIGINTS_REMAINING)
    )
  SIGINTS_RECEIVED += 1
  sys.exit(os.EX_OK)


def run(main, args=None):
  signal.signal(signal.SIGINT, handle_interrupt)
  try:
    main()
  except KeyboardInterrupt:
    sys.exit(os.EX_OK)
  except OSError as e:
    if e.errno in (errno.EADDRINUSE, errno.ENODEV):
      sys.stderr.write('{}\n'.format(e))
      sys.exit(os.EX_OSERR)
    else:
      raise e
  except ServerError as e:
    sys.stderr.write('{}\n'.format(e))
    sys.exit(os.EX_SOFTWARE)



def configure_logging():
  logging.basicConfig(
    datefmt=ISO_8601_TIME_FORMAT,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    level=logging.INFO
  )
