#!/usr/bin/env python3

from distutils.core import setup
import time

setup(
  name='''ThreadedServers''',
  version=time.strftime('%Y.%m.%d.%H.%M.%S', time.gmtime(1524740836)),
  description='''Threaded server modules (ThreadedHTTPSServer, ThreadedMulticastServer, Quickserve, Pacserve).''',
  author='''Xyne''',
  author_email='''ac xunilhcra enyx, backwards''',
  url='''http://xyne.archlinux.ca/projects/python3-threaded_servers''',
  packages=[
    '''ThreadedServers''',
    '''ThreadedServers/PageGenerators'''
  ],
)