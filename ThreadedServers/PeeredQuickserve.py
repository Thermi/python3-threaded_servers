#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2011-2016  Xyne
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

'''
# Overview
The main server is an HTTP(S) server that serves files and provides various
interfaces (HTML, JSON, plaintext, etc.?). The main server may optionally run a
UDP subserver to listen for multicasts. When a multicast is received with a
valid datagram, the sending server is added to the server pool and a direct
reply is sent via an HTTP POST to avoid multicast flooding.

The server also provides various functions via HTTP POST requests. These are
mostly used internally.
'''

import argparse
import ipaddress
import itertools
import json
import logging
import os
import socket
import socketserver
import threading
import urllib.error
import urllib.parse

from .common import (
  add_common_argparse_groups,
  configure_logging,
  DAEMON_THREADS,
  format_uri,
  get_name,
  replace_uri_host_and_get_port,
  run,
  ServerError,
  serverpath_to_localpath,
  serverpath_from_uripath,
  unbound_address,
  VERSION,
)

from .HTTPS import (
  add_HTTPS_argparse_groups,
)

from .Multicast import (
  MulticastPeerManager,
  add_Multicast_argparse_groups,
)

from .Avahi import (
  AvahiPeerManager,
  add_avahi_argparse_groups,
)

from .Quickserve import (
  add_Quickserve_argparse_groups,
  QuickserveServer,
  QuickserveRequestHandler,
)

from .PageGenerators import DEFAULT_PAGE_GENERATORS, DEFAULT_MIMETYPE


NAME = get_name(__file__, __package__)
VERSION_STRING = '{}/{}'.format(NAME, VERSION)

PORT = 8000

# Define a custom multicast group and port.
MULTICAST_GROUP = '224.3.45.66'
MULTICAST_PORT = 15680

TIMEOUT = 3

################################## Functions ###################################

def post_json(url, obj):
  '''
  Post a JSON-encoded object to the given url under the given name and interpret
  the response as a JSON object.
  '''
  data = {
    'json' : json.dumps(obj),
  }
  try:
    typ = obj['type']
  except KeyError:
    typ = 'unknown'
  logging.info('POSTing to {} [type: {}]'.format(url, typ))
  data = urllib.parse.urlencode(data).encode('UTF-8')
  try:
    with urllib.request.urlopen(url, data=data, timeout=TIMEOUT) as f:
      return json.loads(f.read().decode())
  except (urllib.error.URLError, socket.timeout, ValueError) as e:
#     try:
#       logging.error('POST to {} failed (reason: {})'.format(url, e.reason))
#     except AttributeError:
    logging.error('POST to {} failed (error: {})'.format(url, e))
  return None



def remote_file_check(url, paths, hops=0):
  if url[-1] != '/':
    url += '/'
  obj = {
    'type': 'file check',
    'paths': paths,
    'hops' : hops,
  }
  found = post_json(url, obj)
  try:
    for name, location in found.items():
      found[name] = urllib.parse.urljoin(url, location)
  except AttributeError:
    pass
  return found



def remote_directory_listing(url, path, hops=0):
  if url[-1] != '/':
    url += '/'
  obj = {
    'type': 'directory listing',
    'path': path,
    'hops': hops,
  }
  listing = post_json(url, obj)
  try:
    for name, entry in listing.items():
      for e in entry:
        try:
          e['href'] = urllib.parse.urljoin(url, e['href'])
        except KeyError:
          continue
      yield name, entry
  except AttributeError:
    pass


def announce_presence(peer_url, own_url):
  '''
  Post messages to known peers to announce presence.
  '''
  if peer_url[-1] != '/':
    peer_url += '/'
  obj = {
    'type': 'nudge',
    'uri' : own_url,
  }
  return post_json(peer_url, obj)



############################ PeeredQuickserveServer ############################
class PeeredQuickserveServer(
  QuickserveServer,
  MulticastPeerManager,
  AvahiPeerManager
):
  '''
  Multicast-enabled Quickserve server.
  '''

  DEFAULT_PEER_SCHEME = 'http'
  DEFAULT_PEER_PORT = PORT
  MAX_HOPS = 1

  def __init__(
    self,
    *args,
    **kwargs
  ):
    super().__init__(*args, **kwargs)

    self.peers = set()
    self.peer_lock = threading.Lock()

    if self.options.multicast:
      self.start_multicast_threads()

    if self.options.avahi:
      self.start_avahi_threads()



  def handle_peer(self, uri, origin):
    '''
    Handle a peer. This check if the IP and port refer to this server. If not,
    the URI is passed to the maybe_add_peer() method.
    '''
    uri_data = urllib.parse.urlsplit(uri)
    address = ipaddress.ip_address(uri_data.hostname)
    port = uri_data.port
    if not self.is_local_address((address, port)):
      if self.maybe_add_peer(uri, origin):
        self.announce_presence(uri)



  def shutdown(self):
    MulticastPeerManager.shutdown(self)
    QuickserveServer.shutdown(self)



  def get_server_info(self, paths):
    yield from QuickserveServer.get_server_info(self, paths)
    yield from MulticastPeerManager.get_multicast_info(self)
    yield from AvahiPeerManager.get_avahi_info(self)
    if self.options.peers:
      peers = '\n'.join(self.options.peers)
    else:
      peers = None
    yield ('Static Peers', peers)



  def hide_peer_path(self, path):
    '''
    Return True if a peer path should not be accessible on the server. This is
    meant to be overridden in subclasses.
    '''
    return False



  def notify_peers(self, peers=None):
    '''
    Notify peers of presence via an HTTP POST announcement.
    '''
    if not peers:
      peers = self.options.peers
    for uri in peers:
      self.log_message('announcing presence via POST to {}'.format(uri))
      self.announce_presence(uri)



  def maybe_add_peer(self, uri, origin):
    '''
    Add a peer to to the poor of known peers. This may be overridden in
    subclasses to reject peers based on arbitrary criteria. If a peer is
    rejected, the overridden method should return False.
    '''
    if uri in self.options.peers:
      self.log_message('static peer {}'.format(uri))
      return True
    with self.peer_lock:
      if uri not in self.peers:
        self.peers.add(uri)
        self.log_message('added {} ({})'.format(uri, origin))
      return True



  def announce_presence(self, uri):
    '''
    Announce presence to the given URI.
    '''
    first_uri = next(self.get_server_uris())
    server_uri, _ = replace_uri_host_and_get_port(first_uri)
    if announce_presence(uri, server_uri):
      self.log_message('{} acknowledged POST'.format(uri))
    else:
      self.log_message('{} rejected POST'.format(uri))



  # None indicates an error.
  def respond_to_post(self, handler, obj):
    try:
      if obj['type'] == 'file check':
        found = dict()
        unfound = set()
        for serverpath in obj['paths']:
          path = self.resolve_path(serverpath)
          if path is None:
            unfound.add(serverpath)
          else:
            found[serverpath] = serverpath
        if obj['hops'] > 0:
          obj['hops'] -= 1
          # Make a copy to avoid locking while searching other server. A lock or
          # copy is necessary to avoid errors if a peer is removed by another thread
          # during the iteraction. The lock is released during searches to
          # avoid holding it for too long while waiting for responses.
          with self.peer_lock:
            peers = list(self.peers)
          for url in self.options.peers + peers:
            search_results = remote_file_check(url, sorted(unfound), hops=obj['hops'])
            if search_results is None:
              with self.peer_lock:
                try:
                  self.peers.remove(url)
                except KeyError:
                  return
            else:
              for path, location in search_results.items():
                found[path] = location
                try:
                  unfound.remove(path)
                except KeyError:
                  pass
              if not unfound:
                break
        return found

      elif obj['type'] == 'directory listing':
        serverpath = obj['path']
        local_listing = self.resolve_path(serverpath)
        if local_listing and isinstance(local_listing, dict):
          return local_listing
        else:
          return None

      elif obj['type'] == 'nudge':
        uri, port = replace_uri_host_and_get_port(
          obj['uri'],
          handler.client_address[0],
          scheme=self.DEFAULT_PEER_SCHEME,
          port=self.DEFAULT_PEER_PORT
        )
        self.maybe_add_peer(uri, 'POST')
        return True
    except (KeyError, ValueError, TypeError, AttributeError):
      pass
    return None



  def get_navlinks(self, handler, page_generator):
    navlinks = super().get_navlinks(handler, page_generator)
    navlinks.append((
      handler.unparse_path(
        page='peers',
      ),
      'peers',
    ))
    return navlinks



######################## PeeredQuickserveRequestHandler ########################
class PeeredQuickserveRequestHandler(QuickserveRequestHandler):
  '''
  Pacserve request handler.
  '''

  def version_string(self):
    return VERSION_STRING



  def handle_custom(self):
    page_gen = super().handle_custom()
    if not page_gen:
      return None

    try:
      if self.url_qs['page'] == ['peers']:
        peers = sorted(set(self.server.options.peers) | self.server.peers)
        peer_links = (page_gen.format_link(p) for p in peers)
        peer_list = page_gen.format_list(peer_links, ordered=True)
        peer_section = page_gen.format_section(
          'Peer List', content=peer_list, level=2
        )
        page_gen.send_page(self, peer_section, title='Peers')
    except KeyError:
      pass

    return page_gen




  def handle_unresolved(self):
    if not self.server.hide_peer_path(self.url_path):
      search_obj = {
        'type' : 'file check',
        'paths' : [self.url_path],
        'hops' : self.server.MAX_HOPS,
      }
      found = self.server.respond_to_post(self, search_obj)
      try:
        location = found[self.url_path]
        self.log_message('redirecting to {}'.format(location))
        self.redirect(location)
        return True
      except (KeyError, TypeError):
        pass
    return False



  def do_authenticated_GET_or_HEAD(self, extend_resolved=None):
    # Add remote peers.
    def my_extend_resolved(resolved):
      if extend_resolved is not None:
        resolved = extend_resolved(resolved)
      if self.server.options.list_remote:
        with self.server.peer_lock:
          peers = list(self.server.peers)
        for url in self.server.options.peers + peers:
          for name, entries in remote_directory_listing(url, self.url_path):
            try:
              resolved[name].extend(entries)
            except KeyError:
              resolved[name] = list(entries)
      return resolved
    super().do_authenticated_GET_or_HEAD(extend_resolved=extend_resolved)



  def do_authenticated_POST(self):
    try:
      if self.headers['Content-Type'] != 'application/x-www-form-urlencoded':
        raise ValueError('not for me')
      content_length = int(self.headers['Content-Length'])
    except (KeyError, ValueError):
      return super().do_authenticated_POST()
    data = self.rfile.read(content_length)
    obj = None
    for field in data.split(b'&'):
      if field[:5] == b'json=':
        jobj = urllib.parse.unquote_plus(field[5:].decode())
        obj = json.loads(jobj)
        break
    if obj is None or 'type' not in obj:
      self.send_error(400)
      return
    response = self.server.respond_to_post(self, obj)
    self.transfer_json(response)



##################################### Main #####################################

def add_PeeredQuickserve_argparse_groups(parser):

  mcqs_options = parser.add_argument_group(
    title="PeeredQuickserve Options",
  )

  mcqs_options.add_argument(
    '--peer', dest='peers', metavar='<scheme>://<host>:<port>/', default=[], action='append',
    help='Static peers. Pass the option multiple times if necessary. Example: "http://10.0.0.2:8000/"'
  )

  mcqs_options.add_argument(
    '--list-remote', action='store_true',
    help='Include remote files in directory listings.'
  )

  return parser



def main(args=None):
  parser = argparse.ArgumentParser(
    description='%(prog)s - Quickserve with p2p support.',
  )
  parser.add_argument(
    'paths', metavar='<filepath>', nargs='*',
    help='The files and directories to share. These will appear with the same name in server root. Use the filelist option for more advanced features.',
  )
  parser = add_Quickserve_argparse_groups(parser)
  parser = add_PeeredQuickserve_argparse_groups(parser)
  parser = add_common_argparse_groups(parser, port=PORT)
  parser = add_HTTPS_argparse_groups(parser)
  parser = add_Multicast_argparse_groups(
    parser,
    multicast_port=MULTICAST_PORT,
    multicast_group=MULTICAST_GROUP
  )
  parser = add_avahi_argparse_groups(parser)
  args = parser.parse_args(args)

  address = (args.address, args.port)

  page_generators = dict()
  for mimetype, pagegen in DEFAULT_PAGE_GENERATORS.items():
    page_generators[mimetype] = pagegen()
  args.default_mimetype = DEFAULT_MIMETYPE

  handler = PeeredQuickserveRequestHandler
  server = PeeredQuickserveServer(
    address,
    handler,
    args,
    page_generators,
  )
  print(server)
  print("Press ctrl+C to exit.")
  server.notify_peers()
  server.serve_forever()



if __name__ == '__main__':
  configure_logging()
  run(main)
