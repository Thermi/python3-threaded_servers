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



import logging
import threading
import time

import avahi
import dbus
import dbus.exceptions
from gi.repository import GObject as gobject
from dbus.mainloop.glib import DBusGMainLoop


AVAHI_INTERVAL = 300
HTTP_SERVICE_TYPE = '_http._tcp'
HTTPS_SERVICE_TYPE = '_https._tcp'



################################ AvahiAnnouncer ################################

class AvahiAnnouncer(object):
  '''
  Context manager for announcing service via Avahi.
  '''

  def __init__(
    self,
    server,
    domain='',
    host='',
    text=''
  ):
    self.server = server
    self.domain = domain
    self.host = host
    self.text = text
    self.bus = None
    self.group = None



  def __enter__(self):
    self.server.log_message('registering via avahi')
    self.bus = bus = dbus.SystemBus()

    server = dbus.Interface(
      bus.get_object(
        avahi.DBUS_NAME,
        avahi.DBUS_PATH_SERVER
      ),
      avahi.DBUS_INTERFACE_SERVER
    )

    group = dbus.Interface(
      bus.get_object(
        avahi.DBUS_NAME,
        server.EntryGroupNew()
      ),
      avahi.DBUS_INTERFACE_ENTRY_GROUP
    )

    group.AddService(
      avahi.IF_UNSPEC,
      avahi.PROTO_UNSPEC,
      dbus.UInt32(0),
      self.server.get_avahi_service_name(),
      self.server.get_avahi_service_type(),
      self.domain,
      self.host,
      dbus.UInt16(self.server.options.port),
      self.text
    )

    group.Commit()
    self.group = group



  def __exit__(self, typ, value, traceback):
    self.server.log_message('unregistering via avahi')
    if self.group is not None:
      self.group.Reset()
    self.bus.close()



def avahi_announcer(server):
  '''
  Announcer thread.
  '''
  while True:
    try:
      with AvahiAnnouncer(server):
        time.sleep(server.options.avahi_interval)
    except dbus.exceptions.DBusException as e:
      server.log_error('exception encountered in Avahi announcer thread: {}'.format(e))
      time.sleep(server.options.avahi_interval)



################################ AvahiListener #################################

class AvahiListener(object):
  '''
  Connect to the Avahi system bus and listen for services.
  '''
  def __init__(self, server):
    self.server = server
    self.avahi_server = None
    self.mainloop = None




  def resolve_service(
    self,
    interface,
    protocol,
    name,
    service_type,
    domain,
    host,
    aprotocol,
    address,
    port,
    txt,
    flags
  ):
    if service_type == HTTP_SERVICE_TYPE:
      scheme = 'http'
    elif service_type == HTTPS_SERVICE_TYPE:
      scheme = 'https'
    else:
      self.server.log_warning('unrecognized avahi service type: {}'.format(service_type))
      return
    # Wrap IPv6 addresses in brackets.
    if '.' not in address:
      address = '[{}]'.format(address)
    uri = '{}://{}:{:d}/'.format(scheme, address, port)
    self.server.handle_peer(uri, 'avahi')



  def log_error(self, err):
    self.server.log_error('failed to resolve Avahi service: {}'.format(err))



  def handle_avahi(self, interface, protocol, name, service_type, domain, flags):
    if name.startswith(self.server.get_avahi_service_name(prefix_only=True)):
      self.server.log_debug('found service {}@{} [{}]'.format(name, domain, service_type))

  #   if flags & avahi.LOOKUP_RESULT_LOCAL:

      self.avahi_server.ResolveService(
        interface,
        protocol,
        name,
        service_type,
        domain,
        avahi.PROTO_UNSPEC,
        dbus.UInt32(0),
        reply_handler=self.resolve_service,
        error_handler=self.log_error
      )



  def loop(self):
    '''
    Connect to Avahi via the system bus and listen for service announcements.
    '''
    gobject.threads_init()
    dbus.mainloop.glib.threads_init()
    dbus_loop = DBusGMainLoop(set_as_default=False)

    bus = dbus.SystemBus(mainloop=dbus_loop)

    self.avahi_server = server = dbus.Interface(
      bus.get_object(
        avahi.DBUS_NAME,
        avahi.DBUS_PATH_SERVER
      ),
      avahi.DBUS_INTERFACE_SERVER
    )

    service_browser = dbus.Interface(
      bus.get_object(
        avahi.DBUS_NAME,
        server.ServiceBrowserNew(
          avahi.IF_UNSPEC,
          avahi.PROTO_UNSPEC,
          self.server.get_avahi_service_type(),
          'local',
          dbus.UInt32(0)
        )
      ),
      avahi.DBUS_INTERFACE_SERVICE_BROWSER
    )

    service_browser.connect_to_signal('ItemNew', self.handle_avahi)

    self.mainloop = gobject.MainLoop()
    self.mainloop.run()



  def listen(self):
    '''
    Loop wrapper with exception handling.
    '''
    while True:
      try:
        self.loop()
      except dbus.exceptions.DBusException as e:
        self.server.log_error('exception encountered in Avahi listener thread: {}'.format(e))
      time.sleep(self.server.options.avahi_interval)




############################### AvahiPeerManager ###############################

class AvahiPeerManager(object):
  '''
  Manage the avahi announcer and listener threads. This should be subclassed by
  servers that wish to acquire peers through avahi. Subclasses must have the
  following attributes from one of the server classes:

      * options (with all options added by add_avahi_argparse_groups())
      * get_server_uris
      * handler
  '''

  def shutdown(self):
    pass



  def get_avahi_service_type(self):
    '''
    Get the appropriate avahi service type.
    '''
    if self.options.ssl:
      return HTTPS_SERVICE_TYPE
    else:
      return HTTP_SERVICE_TYPE



  def get_avahi_service_name(self, prefix_only=False):
    '''
    Get the version-specific service name.
    '''
    # The handler is a class, not an instance. The method should be static but
    # the base class defines a class method. Invoke the class method here with
    # None as it is not used by the subclass overrides.
    name = self.handler.version_string(None)
    if prefix_only:
      identifier = ''
    else:
      identifier = self.options.port
    return '{}:{}'.format(name, identifier)




  def get_avahi_info(self):
    yield ('Avahi', self.options.avahi)
    if self.options.avahi:
      yield ('Avahi service name', self.get_avahi_service_name())
      yield ('Avahi interval (s)', self.options.avahi_interval)




  def start_avahi_threads(self):
    '''
    Start the listener and announcer threads.
    '''
    self.listener = listener = AvahiListener(self)
    self.avahi_listener_thread = threading.Thread(
      target=listener.listen
    )
    self.avahi_listener_thread.daemon = True
    self.avahi_listener_thread.start()

    self.avahi_announcer_thread = threading.Thread(
      target=avahi_announcer,
      args=(self,)
    )
    self.avahi_announcer_thread.daemon = True
    self.avahi_announcer_thread.start()



############################ Command-line arguments ############################

def add_avahi_argparse_groups(parser, avahi_interval=AVAHI_INTERVAL):
  avahi_options = parser.add_argument_group(
    title="Avahi Options",
    description="Options that affect the behavior of the Avahi integration.",
  )

  avahi_options.add_argument(
    "--avahi", action='store_true',
    help='Use Avahi to announce presence and detect other servers.',
  )

  avahi_options.add_argument(
    '--avahi-interval', metavar='<seconds>', type=int, default=avahi_interval,
    help='The avahi announcement interval. Default: %(default)s.',
  )
  return parser
