#!/bin/bash

# This seems to get Quickserve (non-multicast) working.
# It relies on some "#Python3" and "#Pyton2" comments in the source code.

if [[ -z $1 ]]
then
  echo "usage: $0 <path to ThreadedServers directory>"
  exit 1
fi


cp -R "$1" ThreadedServers3to2
find ThreadedServers3to2 -name '*.py' -exec sed -i '''
  s@socketserver@SocketServer@g
  s@urllib\.parse@urlparse@g
  /import urlparse/ s@$@\nimport urllib@
  s@urllib\.error@urllib2@g
  s@urlparse.quote@urllib.quote@g
  s@http\.server@BaseHTTPServer@g
  /import BaseHTTPServer/ s@$@\nimport SimpleHTTPServer\nimport CGIHTTPServer@g
  s@BaseHTTPServer.SimpleHTTPRequestHandler@SimpleHTTPServer.SimpleHTTPRequestHandler@g
  s@BaseHTTPServer.CGIHTTPRequestHandler@CGIHTTPServer.CGIHTTPRequestHandler@g
  s@super()@super(self.__class__, self)@g
  s@^# \(.* #Python2\)$@\1@
  s@^\(.* #Python3\)$@# \1@
''' '{}' \+