#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2013-2016  Xyne
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

class PageGenerator(object):
  '''
  Base class for implementing page generators.

  All content should be sent through send_page() to ensure consistency. The
  other send_* functions should only prepare the content passed to send_page().
  '''

  def format_section(self, title, content, level=1):
    raise QuickserveError('format_section method is not implemented')

  def format_text(self, text):
    raise QuickserveError('format_text method is not implemented')

  def format_size(self, text):
    raise QuickserveError('format_size method is not implemented')

  def format_time(self, text):
    raise QuickserveError('format_time method is not implemented')

  def format_link(self, href, name=None):
    raise QuickserveError('format_link method is not implemented')

  def format_text_link(self, href):
    '''
    Text links are links that appear in the body of the page, such as file
    and directory links in directory listings. For some outputs it is clearer
    to simply use plaintext.
    '''
    raise QuickserveError('format_text_link method is not implemented')

  def format_list(self, items, ordered=False):
    raise QuickserveError('format_list method is not implemented')

  def format_table(self, rows, with_head=True, alignments=('l',)):
    '''
    If `with_head` is True, the first row is treated as the table headers.

    `alignment` is a tuple of characters representing the alignment of each
    column. If there are fewer characters than columns, the last character
    should be used for the remaining columns.

        l: left
        r: right
        c: center

    '''
    raise QuickserveError('format_table method is not implemented')

  def join(self, blocks):
    '''
    Join multiple blocks together, in order.
    '''
    raise QuickserveError('join method is not implemented')

  def transfer(self, handler, content):
    '''
    Transfer the content using the appropriate method of the handler.
    '''
    raise QuickserveError('transfer method is not implemented')

  def send_page(
    self,
    handler,
    content,
    title=None,
    extra_navlinks=None
  ):
    if title is None:
      title = handler.url_path

    motd = handler.server.get_motd(handler)
    if motd is None:
      motd = None
    else:
      motd = self.format_text(motd)

    navlinks = handler.server.get_navlinks(handler, self)
    if extra_navlinks:
      navlinks.extend((h, n) for h, n in extra_navlinks)
    navlinks = [self.format_link(h, name=n) for h, n in navlinks]

    blocks = list()
    blocks.append(self.format_section(
      'Navigation Links',
      self.format_list(navlinks),
      level=2
    ))
    if motd:
      blocks.append(self.format_section(
        'MOTD',
        motd,
        level=2
      ))
    blocks.append(content)

    self.transfer(
      handler,
      self.format_section(
        title,
        self.join(blocks),
        level=1
      )
    )

  def send_directory_listing(self, handler, entries):
    rows = [('Name', 'Location', 'Size', 'Last Modified')]
#     dirs = list()
#     files = list()
#     for name, entry in entries.items():
#       try:
#         if entry['dir']:
#           dirs.append(name)
#         else:
#           files.append(name)
#       except KeyError:
#         pass
    for name, es in sorted(entries.items(), key=lambda x: x[0]):
      for entry in sorted(
        (e for e in es if 'href' in e),
        key=lambda e: e['href'],
      ):
        if entry.get('dir', False):
          nm = name + '/'
          entry['href'] += '/'
          size = self.format_size(None)
        else:
          nm = name
          size = self.format_size(entry.get('size', None))

        #link = self.format_text_link(entry['href'])
        mtime = self.format_time(entry.get('mtime', None))
        rows.append((nm, entry['href'], size, mtime))

    table = self.format_table(rows, with_head=True, alignments=('l', 'l', 'r'))
    content = self.format_section('Directory Listing', table, level=2)
    self.send_page(handler, content)


  def send_upload_page(self, handler, n):
    raise QuickserveError('join method is not implemented')
