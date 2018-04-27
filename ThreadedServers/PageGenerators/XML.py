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
from ..common import format_size, format_time, AUTHOR, HOMEPAGE

import time
import xml.sax.saxutils

# Re-invent the wheel to avoid dependencies.
# I would rather do this than deal with the monstrosity that is xml.dom.minidom.

##################################### XML ######################################
class XML(object):
  def __init__(self, tag, attrs=None, content=None, indent='  '):
    self.tag = tag
    self.attrs = attrs
    self.content = content
    self.indent = indent

  def format_attrs(self, attrs=None):
    if attrs is None:
      if self.attrs is None:
        return ''
      else:
        attrs = self.attrs
    return ' '.join(
      '{}={}'.format(
        k,
        xml.sax.saxutils.quoteattr(v),
      )
      if v is not None
      else k
      for k,v in sorted(attrs.items(), key=lambda x: x[0])
    )

  def str(self, obj, level=0):
    if isinstance(obj, XML):
      return obj.__str__(level=level)
    elif isinstance(obj, list):
      return '\n'.join(self.str(o, level=level) for o in obj)
    elif not isinstance(obj, str):
      raise QuickserveError(
        'XML objects must be of type XML, list or str, not {}:\n{}'.format(
          type(obj),
          obj
        )
      )
    else:
      return obj

  def __str__(self, level=0):
    indent = self.indent * level
    attrs = self.format_attrs()
    content = self.content
    if attrs:
      attrs = ' ' + attrs
    if content is None:
      return '{}<{}{} />'.format(
        indent,
        self.tag,
        attrs,
      )
    is_text = isinstance(content, str)
    content = self.str(content, level=level+1)
    if is_text or '\n' not in content:
      content = content.lstrip()
      fmt = '{indent}<{tag}{attrs}>{content}</{tag}>'
    else:
      fmt = '{indent}<{tag}{attrs}>\n{content}\n{indent}</{tag}>'
    return fmt.format(
      indent=indent,
      tag=self.tag,
      attrs=attrs,
      content=content,
    )


############################## XHTMLPageGenerator ##############################
class XHTMLPageGenerator(PageGenerator):

  def format_section(self, title, content, level=1):
    tag = 'h{:d}'.format(level)
    return list((
      XML(tag, content=title),
      content
    ))

  def format_text(self, text):
    return XML('pre', content=xml.sax.saxutils.escape(text))


  def format_time(self, t):
    return format_time(t)

  def format_size(self, s):
    if s is None:
      return ''
    else:
      return format_size(s)

  def format_link(self, href, name=None):
    tag = 'a'
    attrs = {'href' : href}
    if name is None:
      name = href
    return XML(tag, attrs=attrs, content=name)

  def format_text_link(self, href):
    return self.format_link(href)

  def format_list(self, items, ordered=False):
    if ordered:
      tag = 'ol'
    else:
      tag = 'ul'
    content = [XML('li', content=item) for item in items]
    return XML(tag, content=content)

  def zip(self, alignments, items):
    alignment = 'left'
    i = 0
    for item in items:
      try:
        a = alignments[i]
        if a == 'r':
          alignment = 'right'
        elif a == 'c':
          alignment = 'center'
        else:
          alignment = 'left'
      except IndexError:
        pass
      i += 1
      yield (alignment, item)

  def iter_table_rows(self, rows):
    for name, href, size, mtime in rows:
      link = self.format_link(href, name)
      if href[0] == '/':
        loc = '.'
      else:
        i = href.index('://') + 3
        j = href.find('/', i)
        if href[-1] == '/':
          loc = href[0:href.rindex('/', 0, -1)+1]
        else:
          loc = href[0:href.rindex('/')+1]
        loc = self.format_link(loc, href[i:j])
      yield link, loc, size, mtime

  def format_table(self, rows, with_head=True, alignments=('l',)):
    table_rows = list()
    if with_head:
      table_headers = [
        XML('th', attrs={'align':a}, content=e) for a, e in self.zip(alignments, rows[0])
      ]
      header_row = XML('tr', content=table_headers)
      table_head = XML('thead', content=header_row)
      rows = rows[1:]
    else:
      table_head = None

    table_rows = [
      XML(
        'tr',
        content = [XML('td', attrs={'align':a}, content=e) for a, e in self.zip(alignments, row)]
      ) for row in self.iter_table_rows(rows)
    ]
    table_body = XML('tbody', content=table_rows)

    if table_head is None:
      return XML('table', content=table_body)
    else:
      return XML('table', content=[table_head, table_body])

  def join(self, blocks):
    return list(blocks)

  def transfer(self, handler, content):
    handler.transfer_html(content)

  html_doctype = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<!--
  Quickserve
    author: {author}
    homepage: {homepage}
-->
'''.format(author=AUTHOR, homepage=HOMEPAGE)

  def get_html(self, content=None):
    attrs = {
      'xmlns' : 'http://www.w3.org/1999/xhtml',
      'xml:lang' : 'en',
      'lang' : 'en'
    }
    return XML('html', attrs=attrs, content=content)

  # Base64-encoded PNG favicon.
  icon_png_b64 = '''iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz
AAAAdgAAAHYBTnsmCAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAGASURB
VDiNY/j//z8DMlZ2jl+jG179Rs0r4zEDAwMHAwMDR2OyZAu6OhhmYkAD7HzCzJxCksKcghL8MLFg
e4HsFY2KyehqGRgYMA3ABjjZmZg9LfgmziqT8yDLAAYGBgZ+bmZufxuB+Z2Z0oZkGcDAwMAgLsQi
EeoosKwkUlyWLAMYGBgYlKTYNWLdhZZ5mPPzkWUAAwMDg74Kp015tNg8RkZGZiZGRkYJZPzv7x+c
hn778Y/hxbvfDC/e/WbQVOAInpQvM5NF3ia0RUjZEB5FzGwcOG0+cfXrJueCO+nIYiwPj6xO5xSS
FOCTVgsm5HQONqZ/////f4FiwP////8KyGklsXBwi3MJS9sQMgQdMDEwMDB8eHTt05ubp6J+fnpz
gywDGBgYGJ5f2PP43d3zUb+/fX6BTwNOAxgYGBgeHd9w/v2DS4l/f33/SpYBDAwMDPcPLNvx4dG1
/H9/fv8lxgAWbIJ3ds2bK2PmowjjX3/w4+P3n/9+3Xv+868VmloAYBOPZZUd3JEAAAAASUVORK5C
YII='''

  def get_html_style(self, extra_style=None, indent=None):
    style = '''html,
body {
  background-color: #ffffff;
  font-family: "Lucida Grande",
               "Lucida Sans Unicode",
               "Lucida Sans",
               Verdana,
               Arial,
               sans-serif;
  margin: 0;
  padding: 0;
}

body {
  width: 100%;
  display: table;
}

h1 {
  background: #366994;
  color: #ffffff;
  font-size: 2.5em;
  font-weight: normal;
  margin: 0;
  padding: 2px 10px 5px 10px;
}
h2 {
  margin: 5px 0;
}
h1+h2 {
  display: none;
}
a {
  color: #366994;
}
#navbar {
  background: #333333;
  color: #eeeeee;
  display: block;
  margin: 0;
  padding: 2px 10px;
}
#navbar li {
  display: inline;
  margin: 0 5px 0 0;
  padding: 0;
}
#navbar li:last-child {
  margin-right: 0;
}
#navbar a {
  color: #ffffff;
  text-decoration: none;
}
#navbar a:hover {
  text-decoration: underline;
}
table {
  font-family: monospace;
  border-spacing:10px 4px;
  white-space: nowrap;
}

#wrapper {
  margin: 0;
  padding: 0 10px;
}
'''
    if extra_style:
      style += extra_style
    style = style.strip()
    if indent:
      style = '\n'.join('{}{}'.format(indent, line) for line in style.split('\n'))
    return style

  def get_html_head(self, title, extra_items=None, extra_style=None):
    head_content = [
      XML(
        'meta',
        attrs = {
          'http-equiv' : 'Content-Type',
          'content' : 'text/html; charset=UTF-8',
        }
      ),
      XML(
        'link',
        attrs = {
          'rel' : 'icon',
          'type' : 'image/png',
          'href' : 'data:image/png;base64,{}'.format(self.icon_png_b64),
        }
      ),
      XML('title', content=title),
      XML(
        'style',
        attrs = {'type' : 'text/css'},
        content=self.get_html_style(extra_style, indent='      '),
      )
    ]
    return XML('head', content=head_content)

  def send_page(
    self,
    handler,
    content,
    title=None,
    extra_navlinks=None,
    extra_head_items=None,
    extra_style=None,
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
      navlinks.extend(self.format_link(h, n) for h, n in extra_navlinks)
    navlinks = [self.format_link(h, name=n) for h, n in navlinks]
    navbar = self.format_list(navlinks)
    navbar.attrs = {'id' : 'navbar'}

    blocks = list()
    blocks.append(self.format_section(
      'Navigation Links',
      navbar,
      level=2
    ))
    wrapped = list()
    if motd:
      wrapped.append(self.format_section(
        'MOTD',
        motd,
        level=2
      ))
    wrapped.append(content)

    wrapper = XML(
      'div',
      attrs={'id' : 'wrapper'},
      content=wrapped,
    )
    blocks.append(wrapper)

    body_content = self.format_section(title, content=blocks)
    body = XML('body', content=body_content)

    head = self.get_html_head(
      title,
      extra_items=extra_head_items,
      extra_style=extra_style,
    )

    html = self.get_html(content=[head, body])
    page = '{}{}'.format(self.html_doctype, html)

    self.transfer(handler, page)


  def send_upload_page(self, handler, n):
    fields = [
      XML(
        'input',
        attrs = {
          'type' : 'file',
          'name' : 'file',
          'size' : '40',
          'multiple' : None,
        }
      ) for i in range(n)
    ]
    field_list = self.format_list(fields, ordered=True)
    submit = XML(
      'input',
      attrs = {
        'type' : 'submit',
        'value' : 'Upload',
        'onclick' : "document.getElementById('status_bar').style.display='inline'",
      }
    )
    form = XML(
      'form',
      attrs = {
        'action' : handler.url_path,
        'enctype' : 'multipart/form-data',
        'method' : 'POST',
      },
      content = [field_list, submit],
    )
    status_bar = XML(
      'span',
      attrs = {
        'id' : 'status_bar',
      },
      content = 'Upload in progress, please wait.',
    )

    upload_block = [form, status_bar]
    content = self.format_section('Upload Files', upload_block, level=2)

    extra_style = '''form li {
  margin-bottom: 0.2em
}
#status_bar {
  display:none;
  text-align:center
}
'''
    self.send_page(
      handler,
      content,
      title=handler.url_path,
      extra_style=extra_style,
    )
