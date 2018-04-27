#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2013  Xyne
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

import errno
import logging
import socket
import socketserver
import struct
import urllib.parse
import threading
import time

from .common import (
  DAEMON_THREADS,
  format_seconds,
  get_all_interfaces,
  get_ip_addresses,
  replace_interfaces_with_ips,
  replace_uri_host_and_get_port,
  unbound_address
)

from .Base import BaseServer

MULTICAST_GROUP = '224.4.4.4'
MULTICAST_PORT = 32768
MULTICAST_INTERVAL = 300

################################## Functions ###################################
def multicast(message, group, ports, bind_address=None):
  try:
    message = message.encode('UTF-8')
  except AttributeError:
    pass

  if isinstance(ports, int):
    ports = (ports,)

  if bind_address is None:
    # Binding to 0.0.0.0 did not work.
    addresses = (ip for (_, ip) in get_all_interfaces())
  else:
    addresses = (bind_address,)

  for address in addresses:
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.bind((address, 0))
        for port in ports:
          sock.sendto(message, (group, port))
          logging.info('multicast message sent to ({}, {:d}) via {}'.format(
            group, port, address
          ))
    except socket.gaierror as e:
#       if e.errno == socket.EAI_NONAME:
#         continue
#       else:
      if bind_address:
        logging.error('announcement failed via {}: {}'.format(address, e.strerror))
      else:
        logging.error('announcement failed: {}'.format(e.strerror))



################################### Threads ####################################

def multicast_announcer(
  message_prefix,
  get_server_uris,
  group=MULTICAST_GROUP,
  ports=MULTICAST_PORT,
  interval=MULTICAST_INTERVAL,
  delay=1,
  interfaces=None
):
  '''
  Periodically announce presence via multicast.
  '''
  time.sleep(delay)
  # If any of the interfaces is an unbound address then all interfaces will be
  # used regardless of the other interfaces. In that case, just use an unbound
  # address.
  if not interfaces or any(unbound_address(i) for i in interfaces):
    interfaces = None
  while True:
    logging.info('announcing presence by multicast (group: {})'.format(group))
    # Do this here to ensure that changes are detected if an interface address
    # changes.
    addresses = set(replace_interfaces_with_ips(interfaces))
    for server_uri in get_server_uris():
      parsed_uri = urllib.parse.urlsplit(server_uri)
      bind_address = parsed_uri.hostname
      if bind_address not in addresses:
        continue
      message, _ = replace_uri_host_and_get_port(server_uri)
      multicast(message_prefix + message, group, ports, bind_address)
    time.sleep(interval)



############################### MulticastServer ################################

class MulticastServer(BaseServer, socketserver.UDPServer, object):
  '''
  Server for listening for multicast announcements.
  '''
  # ThreadingMixIn attribute.
  daemon_threads = DAEMON_THREADS

  def __init__(
    self,
    server_address,
    handler,
    multicast_group,
    *args,
    **kwargs
  ):
    self.multicast_group = multicast_group
    if not unbound_address(server_address[0]):
      for ip in get_ip_addresses(server_address[0]):
        server_address = (ip, server_address[1])
        break
    socketserver.UDPServer.__init__(self, server_address, handler, *args, **kwargs)



  def server_bind(self):
    if self.allow_reuse_address:
      self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.socket.bind(self.server_address)
    mreq = struct.pack(
      "4sl",
      socket.inet_aton(self.multicast_group),
      socket.INADDR_ANY
    )
    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
#     self.server_address = self.get_address_and_port()



############################## MulticastSubserver ##############################
class MulticastSubserver(MulticastServer):
  '''
  Subserver to handle multicast announcements. This is a subclass of the
  multicast listening server. It is run by a main server to handle multicast
  announcements.
  '''
  def __init__(self, main_server, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.main_server = main_server



##################### MulticastSubserverRequestHandler #####################

class MulticastSubserverRequestHandler(socketserver.BaseRequestHandler):
  '''
  The request handler passed to the multicast subserver. This invokes a method
  in the parent server to handle the data from the multicast and add the peer
  to the pool of known peers.
  '''
  def handle(self):
    client_address = self.client_address
    data = self.request[0].decode()
    main_server = self.server.main_server
    multicast_prefix = main_server.get_multicast_prefix()

    l = len(multicast_prefix)
    if data[:l] == multicast_prefix:
      # TODO
      # Catch other errors here
      try:
        uri = data[l:]
        uri, port = replace_uri_host_and_get_port(
          data[l:],
          client_address[0],
          scheme=main_server.DEFAULT_PEER_SCHEME,
          port=main_server.DEFAULT_PEER_PORT
        )
      except ValueError:
        main_server.log_error('invalid multicast message from {}'.format(client_address[0]))
        return
      address = (client_address[0], port)
      main_server.handle_peer(uri, 'multicast')
    else:
      main_server.log_warning('unrecognized multicast message from {}'.format(client_address[0]))



############################# MulticastPeerManager #############################

class MulticastPeerManager(object):
  '''
  Manage the multicast subserver and announcer threads. This should be
  subclassed by servers that wish to acquire peers through multicasts.
  Subclasses must have the following attributes from one of the server classes:

      * options (with all options added by add_Multicast_argparse_groups())
      * handle_peer
      * get_server_uris
  '''

  def shutdown(self):
    try:
      self.multicast_server.shutdown()
    except AttributeError:
      pass



  def get_multicast_prefix(self):
    '''
    The multicast prefix is prepended to the contents of the multicasts. Only
    multicasts with the same prefix will be processed.
    '''
    # The handler is a class, not an instance. The method should be static but
    # the base class defines a class method. Invoke the class method here with
    # None as it is not used by the subclass overrides.
    return self.handler.version_string(None) + ' '



  def get_multicast_info(self):
    if self.options.multicast:
      multicast_address = self.options.multicast_server_address
      if unbound_address(multicast_address):
        multicast_address = 'all interfaces'

      if self.options.multicast_interfaces:
        multicast_interfaces = '\n'.join(self.options.multicast_interfaces)
      else:
        multicast_interfaces = 'all'
      multicast_ports = self.options.multicast_ports
      if isinstance(multicast_ports, list):
        multicast_ports = ' '.join(str(p) for p in multicast_ports)
      yield from (
        ('Multicast listening address', multicast_address),
        ('Multicast listening port', self.options.multicast_server_port),
        ('Multicast group', self.options.multicast_group),
        ('Multicast interval (s)', format_seconds(self.options.multicast_interval)),
        ('Multicast interfaces', multicast_interfaces),
        ('Multicast ports', multicast_ports)
      )
    else:
      yield ('Multicast', False)




  def start_multicast_threads(self):
    '''
    Start the multicast subserver to listen for multicast requests and start a
    thread to periodically announce the presence of this server.
    '''
    self.multicast_server = MulticastSubserver(
      self,
      (self.options.multicast_server_address, self.options.multicast_server_port),
      MulticastSubserverRequestHandler,
      self.options.multicast_group
    )
    self.multicast_server_thread = threading.Thread(
      target=self.multicast_server.serve_forever
    )
    self.multicast_server_thread.daemon = True #DAEMON_THREADS
    self.multicast_server_thread.start()

    self.multicast_announcer_thread = threading.Thread(
      target=multicast_announcer,
      args=(
        self.get_multicast_prefix(),
        self.get_server_uris
      ),
      kwargs={
        'group' : self.options.multicast_group,
        'ports' : self.options.multicast_ports,
        'interval' : self.options.multicast_interval,
        'interfaces' : self.options.multicast_interfaces,
      }
    )
    self.multicast_announcer_thread.daemon = True #DAEMON_THREADS
    self.multicast_announcer_thread.start()



################################# TestHandler ##################################

class TestHandler(socketserver.BaseRequestHandler, object):
  '''
  Simple request hander for basic testing.
  '''
  def handle(self):
    print("{}:\n{}".format(
      self.client_address[0],
      self.request[0]
    ))




############################ Command-line arguments ############################

def add_Multicast_argparse_groups(
  parser,
  multicast_address='0.0.0.0',
  multicast_port=MULTICAST_PORT,
  multicast_group=MULTICAST_GROUP,
  multicast_interval=MULTICAST_INTERVAL
):
  multicast_options = parser.add_argument_group(
    title="Multicast Options",
    description="Options that affect the behavior of the multicast (sub)server system.",
  )

  multicast_options.add_argument(
    "--multicast", action='store_true',
    help='Use multicasting to announce presence and detect other servers.',
  )

  multicast_options.add_argument(
    "--multicast-server-address", metavar='<interface|address>', default=multicast_address,
    help='The multicast server listening address. Default: %(default)s.',
  )

  multicast_options.add_argument(
    '--multicast-server-port', metavar='<port>', type=int, default=multicast_port,
    help='The multicast server listening port. Default: %(default)s.',
  )

  multicast_options.add_argument(
    '--multicast-group', metavar='<group>', default=multicast_group,
    help='The multicast group. Default: %(default)s.',
  )

  multicast_options.add_argument(
    '--multicast-interval', metavar='<seconds>', type=int, default=multicast_interval,
    help='The multicast announcement interval. Default: %(default)s.',
  )

  multicast_options.add_argument(
    "--multicast-interface", metavar='<interface|address>', dest="multicast_interfaces",
    default=[], action='append',
    help='The interface or address through which to announce presence with multicast packets. If not given, all interfaces on which the server is listening are used. Interfaces on which the server is not listening are ignored.',
  )

  multicast_options.add_argument(
    '--multicast-ports', metavar='<port>', type=int, nargs='+', default=multicast_port,
    help='The multicast ports to which to send announcement messages. Default: %(default)s.',
  )
  return parser



if __name__ == "__main__":
  server = MulticastServer(
    ('', MULTICAST_PORT),
    TestHandler,
    MULTICAST_GROUP
  )
  server.serve_forever()
