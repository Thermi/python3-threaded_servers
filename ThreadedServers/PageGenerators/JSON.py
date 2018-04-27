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

class JSONPageGenerator(PageGenerator):
  '''
  Generate JSON pages.
  '''

  def format_section(self, title, content, level=1):
    return {title : content}

  def format_text(self, text):
    return text

  def format_time(self, t):
    return t

  def format_size(self, s):
    return s

  def format_link(self, href, name=None):
    if name is None:
      name = href
    return {name : href}

  def format_text_link(self, href):
    return href

  def format_list(self, items, ordered=False):
    return list(items)

  def format_table(self, rows, with_head=True, alignments=('l',)):
    if with_head:
      table = list()
      headers = rows[0]
      for row in rows[1:]:
        table.append(dict((h, e) for h, e in zip(headers, row)))
      return table
    else:
      return list(rows)

  def join(self, blocks):
    return list(blocks)

  def transfer(self, handler, content):
    handler.transfer_json(content, indent='  ', sort_keys=True)

  def send_upload_page(self, handler, n):
    content = {
      "type" : "upload form",
      "form" : {
        "action" : handler.unparse_path(ignored_qs=('upload',)),
        "enctype" : "multipart/form-data",
        "method" : "post",
        "inputs" : list({'type':'file','name':'file'} for i in range(1, n+1))
      },
    }
    self.send_page(handler, content)
