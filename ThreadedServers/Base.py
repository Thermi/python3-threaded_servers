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

from .common import (
  DAEMON_THREADS,
  ServerError,
  get_all_interfaces,
)

import logging
import socket
import socketserver


################################## BaseServer ##################################
class BaseServer(
  socketserver.ThreadingMixIn,
  object
):
  '''
  Base server class from which all others in this package should inherit.
  '''

  # ThreadingMixIn attribute.
  daemon_threads = DAEMON_THREADS


  def __init__(self, options):
    self.options = options



  def log_message(self, msg):
    logging.info(msg)



  def log_error(self, msg):
    logging.error(msg)



  def log_warning(self, msg):
    logging.warn(msg)



  def log_debug(self, msg):
    logging.debug(msg)



  def get_address_and_port(self):
    return self.socket.getsockname()[:2]



  def get_address_header_and_string(self):
    address, port = self.get_address_and_port()
    lines = list()
    l = 0
    for ifname, ip in self.local_ifnames_and_ips():
      if ifname is None:
        ifname = '?'
      ifname += ':'
      l = max(len(ifname), l)
      lines.append((ifname, ip))
    fmt = '{{:{:d}s}} {{}}'.format(l)
    lines = sorted(fmt.format(a,b) for a,b in lines)
    if len(lines) > 1:
      header = 'Addresses'
      string = '\n'.join(lines)
    else:
      header = 'Address'
      string = lines[0]
    return header, string



  def get_scheme(self):
    '''
    This should return a scheme for constructing URIs.
    '''
    raise ServerError('get_scheme() is not implemented')


  def local_ips(self):
    '''
    Return an iterator over the detected local IP addresses.
    '''
    try:
      if self.options.address:
        yield self.options.address
        return
    except AttributeError:
      pass
    for _, ip in get_all_interfaces():
      yield ip



  def is_local_address(self, address):
    '''
    Check if an address is local. Returns True if the address is listed by
    the local_ips() method.
    '''
    port = self.options.port
    for ip in self.local_ips():
      if address == (ip, port):
        return True
    return False



  def local_ifnames_and_ips(self):
    '''
    Return an iterator over the detected interfaces and local IP addresses.
    '''
    try:
      if self.options.address:
        for ifname, ip in get_all_interfaces():
          if ip == self.options.address:
            yield ifname, ip
            return
        else:
          yield None, self.options.address
        return
    except AttributeError:
      pass
    yield from get_all_interfaces()
