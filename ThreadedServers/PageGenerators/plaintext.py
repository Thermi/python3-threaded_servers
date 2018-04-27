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

from .base import PageGenerator
from ..common import format_size, format_time

class PlaintextPageGenerator(PageGenerator):
  '''
  Generate plaintext (markdown) pages.
  '''

  def format_section(self, title, content, level=1):
    return '{hsh} {title}\n\n{content}\n'.format(
      hsh='#' * level,
      title=title,
      content=content
    )

  def format_text(self, text):
    return text

  def format_time(self, t):
    return format_time(t)

  def format_size(self, s):
    if s is None:
      return ''
    else:
      return format_size(s)

  def format_link(self, href, name=None):
    if name is None:
      return '<{}>'.format(href)
    else:
      return '[{}]({})'.format(name, href)

  def format_text_link(self, href):
    return href

  def create_format_string(self, widths, alignments):
    for w, a in zip(widths, alignments):
      if a == 'r':
        c = '>'
      elif a == 'c':
        c = '^'
      else:
        c = '<'
      yield '{{:{}{:d}s}}'.format(c, w)

  def format_list(self, items, ordered=False):
    if ordered:
      items = list(items)
      return '\n'.join('{:d}) {}'.format(i+1, items[i]) for i in range(len(items)))
    else:
      return '\n'.join('* {}'.format(item) for item in items)

  def format_table(self, rows, with_head=True, alignments=('l',)):
    if with_head:
      headers = [str(h) for h in rows[0]]
      rows = [[str(e) for e in r] for r in rows[1:]]
    else:
      headers = None
      rows = [[str(e) for e in r] for r in rows]

    widths = [len(x) for x in headers]
    for row in rows:
      i = 0
      for entry in row:
        w = len(entry)
        try:
          widths[i] = max(widths[i], w)
        except IndexError:
          widths.append(w)
        i += 1

    alen = len(alignments)
    cols = len(widths)
    if alen < cols:
      alignments += alignments[-1:] * (cols * alen)
#     elif alen > cols:
#       alignments = alignments[:cols]

    fmt = ' '.join(self.create_format_string(widths, alignments)) + '\n'
    separators = tuple('-' * w for w in widths)

    table = fmt.format(*headers)
    table += fmt.format(*separators)
    for r in rows:
      table += fmt.format(*r)
    return table

  def join(self, blocks):
    return '\n'.join(blocks)

  def transfer(self, handler, content):
    handler.transfer_plaintext(content)

  def send_upload_page(self, handler, n):
    text = '''Submit multipart/form-data to {path} using the HTTP POST method. Each file should be submitted in a file input named "file".

To submit files with `curl`, use

    curl -F file=@/path/to/file {url}
'''.format(
      path=handler.url_path,
      url='...', # TODO: use server address
    )
    text = self.format_text(text)
    content = self.format_section('Upload Files', text, level=2)
    self.send_page(handler, content)
