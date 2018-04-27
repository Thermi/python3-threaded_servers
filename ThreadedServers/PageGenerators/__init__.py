#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .plaintext import PlaintextPageGenerator
from .JSON import JSONPageGenerator
from .XML import XHTMLPageGenerator

DEFAULT_MIMETYPE = 'application/xhtml+xml'

DEFAULT_PAGE_GENERATORS = {
  'application/json' : JSONPageGenerator,
  'application/xhtml+xml' : XHTMLPageGenerator,
  'text/plain' : PlaintextPageGenerator,
}
