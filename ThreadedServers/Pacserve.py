#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2011-2013  Xyne
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


from .common import (
  add_common_argparse_groups,
  configure_logging,
  get_name,
  run,
  ServerError,
  serverpath_to_localpath,
  serverpath_from_uripath,
  VERSION,
)

from .HTTPS import (
  add_HTTPS_argparse_groups,
)

from .Multicast import (
  add_Multicast_argparse_groups,
)

from .Avahi import (
  add_avahi_argparse_groups,
)

from .Quickserve import (
  add_Quickserve_argparse_groups,
)

from .PeeredQuickserve import (
  remote_file_check,
  add_PeeredQuickserve_argparse_groups,
  PeeredQuickserveServer,
  PeeredQuickserveRequestHandler,
)

from .PageGenerators import DEFAULT_PAGE_GENERATORS, DEFAULT_MIMETYPE

import pycman

import argparse
import posixpath
import socket
import urllib.parse


NAME = get_name(__file__, __package__)
VERSION_STRING = '{}/{}'.format(NAME, VERSION)

PORT = 15678
MULTICAST_GROUP = '224.3.45.67'
MULTICAST_PORT = 15679

SERVER_PACKAGE_DIRECTORY = 'pkg'
PACMAN_PSEUDODIRECTORY = 'pacman'

################################## Functions ###################################

def search_pkgs(url, pkgnames, hops=1):
  results = remote_file_check(
    url,
    [posixpath.join(SERVER_PACKAGE_DIRECTORY, p) for p in pkgnames],
    hops=hops
  )
  if results is None:
    return None
  else:
    return dict(
      (posixpath.basename(path), uri) for path, uri in results.items()
    )



def is_package(path):
  return ('.pkg.' in posixpath.basename(path))


################################ PacserveServer ################################
class PacserveServer(PeeredQuickserveServer):
  '''
  Pacserve server.
  '''

  def __init__(
    self,
    *args,
    **kwargs
  ):
    super().__init__(*args, **kwargs)
    self.conf = pycman.config.PacmanConfig(conf=self.options.pacman_conf)



  def clean_house(self):
    super().clean_house()
    # Necessary due to ordering conflict.
    try:
      try:
        self.paths[SERVER_PACKAGE_DIRECTORY].extend(self.conf.options['CacheDir'])
      except KeyError:
        self.paths[SERVER_PACKAGE_DIRECTORY] = list(self.conf.options['CacheDir'])
    except AttributeError as e:
      pass



  def hide_peer_path(self, path):
    return not (
      getattr(self.options, 'trust_pacserve_peers', False) \
      or is_package(path)
    )




############################ PacserveRequestHandler ############################
class PacserveRequestHandler(PeeredQuickserveRequestHandler):
  '''
  Pacserve request handler.
  '''

  def version_string(self):
    return VERSION_STRING



  def parse_path(self):
    super().parse_path()

    # FIXME
    # Remove these hacks if Pacman ever gets true support for query strings.

    # Server = http://localhost:15678/pacman/$repo/$arch
    path_components = self.url_path.strip('/').split('/')
    try:
      if path_components[0] == PACMAN_PSEUDODIRECTORY:
        self.url_qs['repo'] = [path_components[1]]
        self.url_qs['arch'] = [path_components[2]]
        self.url_path = '{}/{}'.format(
          SERVER_PACKAGE_DIRECTORY,
          path_components[-1]
        )
        return
    except IndexError:
      pass

    # Server = http://localhost:15678/pkg/?repo=$repo&arch=$arch&file=
    try:
      self.url_path = '{}/{}'.format(
        SERVER_PACKAGE_DIRECTORY,
        posixpath.basename(self.url_qs['file'][0])
      )
      return
    except KeyError:
      pass



  def redirect_to_mirror(self):
    try:
      arch = self.url_qs['arch'][0]
      repo = self.url_qs['repo'][0]
      urls = self.server.conf.repos[repo]
    except KeyError:
      self.send_error(400)
      return True

    local_addresses = set(
      (ip, self.server.options.port) for ip in self.server.local_ips()
    )
    name = posixpath.basename(self.url_path)

    for url in urls:
      url_data = urllib.parse.urlsplit(url)
      if url_data.scheme == 'file':
        continue
      elif url_data.scheme == self.server.get_scheme():
        skip = False
        if url_data.port is None:
          # TODO
          # Make this more robust.
          if url_data.scheme is 'https':
            port = 443
          else:
            port = 80
        else:
          port = url_data.port
        for sockaddr in set(
          sockaddr for family, typ, proto, canonname, sockaddr in socket.getaddrinfo(
            url_data.hostname,
            port
          )
        ):
          server_address = sockaddr[:2]
          if server_address in local_addresses:
            skip = True
            break
        if skip:
          continue
      url = url.replace('$arch', arch).replace('$repo', repo)
      if url[-1] != '/':
        url += '/'
      try:
        agent = self.headers['User-Agent'].split('/', 1)[0]
      except KeyError:
        agent = None
      # Pacman/libalpm bug
      if agent == 'pacman':
        url += name
      else:
        url = urllib.parse.urljoin(url, urllib.parse.quote(name))
      self.log_message('redirecting to {}'.format(url))
      if agent == 'pacman':
        self.log_message('tell the Pacman devs to url-decode their redirects')
      self.redirect(location=url, status_code=303)
      return True
    return False


# TODO
# Custom database handling?
#   def handle_custom(self):
#     page_gen = super().handle_custom()
#     return page_gen



  def handle_unresolved(self):
    return (
      super().handle_unresolved() or \
      self.redirect_to_mirror()
    )


##################################### Main #####################################

def add_Pacserve_argparse_groups(parser):

  pac_options = parser.add_argument_group(
    title="Pacserve Options",
  )

  pac_options.add_argument(
    '--pacman-conf', metavar='<filepath>', default='/etc/pacman.conf',
    help='The Pacman configuration file to use. Default: %(default)s'
  )

  pac_options.add_argument(
    '--trust-pacserve-peers', action='store_true',
    help='Allow the server to redirect database, signature and other non-package request to its peers instead of immediately redirecting to a mirror. This can be useful for some setups but you should only use it if you trust the peers or know exactly what you are doing.'
  )

  return parser



def main(args=None):
  parser = argparse.ArgumentParser(
    description='%(prog)s - share Pacman packages over your LAN and beyond',
  )
  parser.add_argument(
    'paths', metavar='<filepath>', nargs='*',
    help='Additional files and directories to share. These will appear with the same name in server root. Use the filelist option for more advanced features.',
  )
  parser = add_Pacserve_argparse_groups(parser)
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

  handler = PacserveRequestHandler
  server = PacserveServer(
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
