#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2009-2016  Xyne
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


import argparse
# import errno #Python2
import itertools
import json
import os
import posixpath
import re
import stat
import threading
import time
import urllib.parse

from .common import (
  add_common_argparse_groups,
  configure_logging,
  DEFAULT_CHUNK_SIZE,
  get_name,
  run,
  ServerError,
  serverpath_to_localpath,
  serverpath_from_uripath,
  unbound_address,
  unparse_qs,
  VERSION,
)

from .HTTPS import (
  add_HTTPS_argparse_groups,
  BaseHTTPSRequestHandler,
  HTTPSServer,
  TAR_COMPRESSIONS,
  get_tar_mtime,
  add_tar_extension
)

from .PageGenerators import DEFAULT_PAGE_GENERATORS, DEFAULT_MIMETYPE

from .common import format_size

NAME = get_name(__file__, __package__)
VERSION_STRING = '{}/{}'.format(NAME, VERSION)

################################## Functions ###################################



def _get_file_data(path):
  '''
  Return a subset of stat data for a given path.

  The return value is a dictionary containing sizes, mtimes, and a boolean to
  indicate directories.
  '''
  try:
    st = os.stat(path)
    return {
      'mtime' : int(st.st_mtime),
      'size' : st.st_size,
      'dir' : stat.S_ISDIR(st.st_mode),
    }
  except FileNotFoundError: #Python3
#   except OSError as e: #Python2
#     if e.errno == errno.ENOENT: #Python2
      return None
#     else: #Python2
#       raise e #Python2



def _resolve_paths(paths):
  for k, vs in paths.items():
    if isinstance(vs, str):
      paths[k] = os.path.abspath(vs)
    else:
      paths[k] = list(os.path.abspath(v) for v in vs)
  return paths



def _iterate_filelist(f):
  for line in f:
    line = line.strip()
    if not line or line[0] == '#':
      continue
    yield line



def _iterate_paths(paths):
  for path in paths:
    path = os.path.abspath(path)
    name = os.path.basename(path)
    try:
      if os.path.isdir(path):
        yield name, [path]
      else:
        yield name, path
    except FileNotFoundError: #Python3
#     except OSError as e: #Python2
#       if e.errno == errno.ENOENT: #Python2
        pass
#       else: #Python2
#         raise e #Python2



def load_paths_from_file(fpath, last_loaded=None):
  if last_loaded:
    last_paths, last_time = last_loaded
    mtime = os.path.getmtime(fpath)
    if mtime <= last_time:
      return last_paths, last_time

  t = time.time()
  with open(fpath, 'r') as f:
    c = f.read(1)
    f.seek(0, os.SEEK_SET)
    if c == '{':
      paths = _resolve_paths(json.load(f))
    else:
      paths = dict(_iterate_paths(_iterate_filelist(f)))
  return paths, t



def load_paths(newpaths, loadedpaths=None):
  '''
  Load paths into a paths dictionary.

  Files map their basenames to their paths. Directories map their basenames to
  lists. This allows a single visible directory to include contents from
  multiple real directories by adding more paths to the list.
  '''
  if loadedpaths is None:
    loadedpaths = dict()
  if isinstance(newpaths, dict):
    for k, vs in newpaths.items():
      if isinstance(vs, str):
        loadedpaths[k] = vs
      else:
        loadedpaths[k] = list(os.path.abspath(v) for v in vs)
  else:
    for path in newpaths:
      path = os.path.abspath(path)
      name = os.path.basename(path)
      try:
        if os.path.isdir(path):
          path = [path]
      except FileNotFoundError: #Python3
#       except OSError as e: #Python2
#         if e.errno == errno.ENOENT: #Python2
          continue
#         else: #Python2
#           raise e #Python2
      loadedpaths[name] = path
  return loadedpaths



############################### QuickserveServer ###############################
class QuickserveServer(HTTPSServer):
  '''
  Baseclass file server.
  '''

  MAX_UPLOAD_COUNT = 0xff

  def __init__(
    self,
    address,
    handler,
    options,
    page_generators,
    *args,
    **kwargs
  ):
    '''
    paths:
      A map of server paths to lists of localdirectories or single files. If a
      list is given then the contents of the directories will appear to be
      merged in a single directory on the server. The order of the list
      determines which item will be displayed if the same entry appears in
      multiple directories.
    '''
    super().__init__(address, handler, options, *args, **kwargs) #Python3
#     HTTPSServer.__init__(self, address, handler, options, *args, **kwargs) #Python2

    if self.options.tar:
      self.options.tar = sorted(set(self.options.tar))

    self.page_generators = page_generators

    self.motd = None
    self.motd_time = 0

    self.filelist_time = 0
    self.filterlist_time = 0

    self.upload_lock = threading.Lock()
    self.upload_paths = set()

    self.paths = dict()
    self.filters = list()

    self.clean_house()



  def load_paths(self):
    paths = None
    try:
      if self.options.filelist:
        last_time = self.filelist_time
        paths, self.filelist_time = load_paths_from_file(
          self.options.filelist,
          (self.paths, last_time)
        )
        if self.filelist_time != last_time:
          self.log_message('loaded {}'.format(self.options.filelist))
    except FileNotFoundError as e: #Python3
#     except OSError as e: #Python2
#       if e.errno == errno.ENOENT: #Python2
        raise ServerError(str(e))
#       else: #Python2
#         raise e #Python2
    except AttributeError as e:
      pass

    if paths is None:
      paths = dict()

    try:
      if isinstance(self.options.paths, dict):
        paths.update(self.options.paths)
      else:
        paths.update(_iterate_paths(self.options.paths))
    except AttributeError:
      pass

    self.paths = paths



  def load_filters(self):
    filters = list()
    try:
      if self.options.filterlist:
        mtime = os.path.getmtime(self.options.filterlist)
        if self.filters is None \
        or os.path.getmtime(self.options.filterlist) > self.filterlist_time:
          with open(self.options.filterlist, 'r') as f:
            for line in f:
              line = line.strip()
              if not line or line[0] == '#':
                continue
              filters.append((re.compile(line[1:]), line[0] != 'i'))
          self.filterlist_time = mtime
          self.log_message('loaded {}'.format(self.options.filterlist))
    except FileNotFoundError as e: #Python3
#     except OSError as e: #Python2
#       if e.errno == errno.ENOENT: #Python2
        raise ServerError(str(e))
#       else: #Python2
#         raise e #Python2
    except AttributeError:
      pass

    try:
      for line in self.options.filters:
        filters.append((re.compile(line[1:]), line[0] != 'i'))
    except (AttributeError, TypeError):
      pass

    self.filters = filters



  def clean_house(self):
    super().clean_house()
    with self.lock:
      self.load_paths()
      self.load_filters()



  def get_server_info(self, paths):
    '''
    Return a list of 2-tuples containing data to be displayed in __str__.
    '''
    address, port = self.get_address_and_port()
    address_header, address_string = self.get_address_header_and_string()

    if self.options.tar:
      compressions = 'Enabled: ' + ' '.join(self.options.tar)
    else:
      compressions = 'Disabled'

    yield from (
      ('PID', os.getpid()),
      (address_header, address_string),
      ('Port', port),
      ('Filelist', getattr(self.options, 'filelist', None)),
      ('Filterlist', getattr(self.options, 'filterlist', None)),
      ('MOTD', getattr(self.options, 'motd', None)),
      ('Upload directory', getattr(self.options, 'upload_directory', None)),
      ('Tar', compressions),
      ('Paths', paths),
    )



  def __str__(self):
    if self.paths:
      paths = '\n'.join(
          '{}\n  {}'.format(
            k,
            vs if isinstance(vs, str) else '\n  '.join(vs)
          ) for k, vs in self.paths.items()
        )
    else:
      paths = None
    info = tuple(self.get_server_info(paths))
    w = max(len(i[0]) for i in info)
    string = self.__class__.__name__ + '\n'
    for k, v in info:
      k = k.ljust(w)
      v = str(v).strip()
      if '\n' in v:
        v = '\n    ' + v.replace('\n', '\n    ')
      else:
        v = ' ' + v
      string += '  {}{}\n'.format(k, v)
    return string



  def hide_path(self, serverpath):
    '''
    Return True to hide the given server path.

    This function must not call functions from the os.path module. Use the
    posixpath module instead.
    '''
    if not serverpath or serverpath == '/':
      return False
    name = posixpath.basename(serverpath)
    if name[0] == '.' and not self.options.show_hidden:
      return True
    else:
      hide = False
      try:
        for pattern, is_hidden in self.filters:
          if pattern.search(serverpath):
            hide = is_hidden
      except AttributeError:
        pass
      return hide



  def resolve_path(self, serverpath, dir_listings=True):
    '''
    Resolve a server path to a local file path or directory listing.

    dir_listings:
      If True, return directory paths as listings, otherwise as strings.
    '''
    if self.hide_path(serverpath):
      return None

    serverpath = serverpath.lstrip('/')

    try:
      if self.options.root:
        localpath = serverpath_to_localpath(serverpath, self.options.root)
        try:
          st = os.stat(localpath)
          if stat.S_ISDIR(st.st_mode):
            return self.directory_listing(serverpath, localpath)
          elif st.st_mode & (stat.S_IFLNK | stat.S_IFREG | stat.S_IFIFO):
            return localpath
          else:
            return None
        except FileNotFoundError: #Python3
#         except OSError as e: #Python2
#           if e.errno == errno.ENOENT: #Python2
            return None
#           else: #Python2
#             raise e #Python2
    except AttributeError:
      pass

    if not serverpath:
      return self.root_listing()

    # Work backwards from the end of the path until the root matches a path.
    serverpath_root = serverpath
    serverpath_subroot = ''
    serverpath_subpath = ''
    mapped = None
    while mapped is None:
      try:
        mapped = self.paths[serverpath_root]
      except KeyError:
        if serverpath_subroot:
          if serverpath_subpath:
            serverpath_subpath = posixpath.join(serverpath_subroot, serverpath_subpath)
          else:
            serverpath_subpath = serverpath_subroot
        try:
          serverpath_root, serverpath_subroot = serverpath_root.rsplit('/', 1)
        except ValueError:
          break
    if mapped is None:
      return None

    # Single file.
    if isinstance(mapped, str):
      # This requested path is asking for a subpath of a file.
      if serverpath_subroot:
        return None
      else:
        return mapped
    else:
      # Subpath of mapped directory.
      if serverpath_subroot:
        if serverpath_subpath:
          serverpath_subpath = posixpath.join(serverpath_subroot, serverpath_subpath)
        else:
          serverpath_subpath = serverpath_subroot

        for localpath in mapped:
          localpath = serverpath_to_localpath(serverpath_subpath, start=localpath)
          try:
            st = os.stat(localpath)
            if stat.S_ISDIR(st.st_mode):
              if dir_listings:
                return self.directory_listing(serverpath, localpath)
              else:
                return localpath
            elif st.st_mode & (stat.S_IFLNK | stat.S_IFREG | stat.S_IFIFO):
              return localpath
            else:
              continue
          except FileNotFoundError: #Python3
#           except OSError as e: #Python2
#             if e.errno == errno.ENOENT: #Python2
              continue
#             else: #Python2
#               raise e #Python2
        else:
          return None
      # Mapped directory
      elif dir_listings:
        listing = dict()
        for localpath in reversed(mapped):
          listing.update(self.directory_listing(serverpath, localpath))
        return listing
      else:
        return mapped[0]
    return None



  def directory_listing(self, serverpath, localpath):
    '''
    Return a dictionary of items in a directory.
    '''
    listing = dict()
    try:
      for item in os.listdir(localpath):
        if self.hide_path(posixpath.join(serverpath, item)):
          continue
        filepath = os.path.join(localpath, item)
        entry = _get_file_data(filepath)
        if entry:
#           entry['href'] = urllib.parse.urljoin(serverpath, urllib.parse.quote(item))
          entry['href'] = posixpath.join('/', serverpath, urllib.parse.quote(item))
          listing[item] = [entry]
          if entry['dir'] and self.options.tar:
            mtime = get_tar_mtime(localpath)
            for compression in self.options.tar:
              tar_item = add_tar_extension(item, compression)
              href= '{}/?tar={}'.format(
                posixpath.join('/', serverpath, urllib.parse.quote(item)),
                compression
              )
              e = {
                'dir' : False,
                'mtime': mtime,
                'href': href
              }
              listing[tar_item] = [e]

    except FileNotFoundError: #Python3
#     except OSError as e: #Python2
#       if e.errno == errno.ENOENT: #Python2
        pass
#       else: #Python2
#         raise e #Python2
    return listing



  def root_listing(self):
    '''
    Variation of directory_listing() for special handling of the root directory.
    '''
    listing = dict()
    for path, mapped in self.paths.items():
      if self.hide_path(path):
        continue
      mapped_one = isinstance(mapped, str)
      if mapped_one:
        entry = _get_file_data(mapped)
      else:
        entry = None
        for p in mapped:
          e = _get_file_data(p)
          if e:
            if not entry:
              entry = e
            else:
              entry['mtime'] = max(entry['mtime'], e['mtime'])
      if entry:
        entry['href'] = urllib.parse.quote('/' + path)
        listing[path] = [entry]

        if entry['dir'] and self.options.tar:
          if mapped_one:
            mtime = get_tar_mtime(mapped)
          else:
            mtime = max(get_tar_mtime(m) for m in mapped)
          for compression in self.options.tar:
            tar_item = add_tar_extension(path, compression)
            href= '{}/?tar={}'.format(
              urllib.parse.quote('/' + urllib.parse.quote(path)),
              compression
            )
            e = {
              'dir' : False,
              'mtime': mtime,
              'href': href
            }
            listing[tar_item] = [e]
    return listing



  def get_navlinks(self, handler, page_generator):
    navlinks = [
      ('..', 'up'),
      ('/', 'root'),
    ]
    for mimetype, page_gen in sorted(
      handler.server.page_generators.items(),
      key=lambda x: x[0],
    ):
      if page_gen.__class__ != page_generator.__class__:
        navlinks.append((
          handler.unparse_path(extra_qs={'mimetype' : [mimetype]}),
          mimetype,
        ))
    if self.options.upload_dir:
      try:
        n = int(handler.url_qs['count'][0])
        if n >= self.MAX_UPLOAD_COUNT:
          n = self.MAX_UPLOAD_COUNT
        else:
          handler.url_qs['count'] = ['{:d}'.format(n+1)]
          navlinks.append(
            (handler.unparse_path(page='upload'), 'upload ++')
          )
        if n > 1:
          handler.url_qs['count'] = ['{:d}'.format(n-1)]
          navlinks.append(
            (handler.unparse_path(page='upload'), 'upload --')
          )
        handler.url_qs['count'] = ['{:d}'.format(n)]
      except KeyError:
        navlinks.append((
          handler.unparse_path(
            page='upload',
            extra_qs={'count' : ['1']}
          ),
          'upload',
        ))
      except ValueError:
        pass
    return navlinks



  def get_motd(self, handler):
    '''
    Return an MOTD message if one has been set, else an emptry string.
    '''
    try:
      if self.options.motd:
        mtime = os.path.getmtime(self.options.motd)
        if self.motd is None \
        or mtime > self.motd_time:
          with open(self.options.motd, 'r') as f:
            self.motd = f.read()
          self.motd_time = mtime
          self.log_message('loaded {}'.format(self.options.motd))
    except FileNotFoundError as e: #Python3
#     except OSError as e: #Python2
#       if e.errno == errno.ENOENT: #Python2
        pass #Python2
#       else: #Python2
#         raise e #Python2
    except AttributeError:
      pass
    return self.motd



  def get_upload_path(self, handler, filename):
    '''
    Return a local file path for saving an uploaded file.

    The returned path is temporary reserved to prevent other threads from using
    the same path before a file has been created. The path should be released
    with release_upload_path once the file has been created or the path is no
    longer needed.
    '''
    dpath = self.options.upload_dir
    with self.upload_lock:
      try:
        os.makedirs(dpath, exist_ok=True)
      # Raised for permission errors.
      except FileExistsError:
        pass
      try:
        overwrite = self.options.upload_overwrite
      except AttributeError:
        overwrite = False
      path = serverpath_to_localpath(filename, start=dpath)
      if overwrite:
        return path
      else:
        candidate_path = path
        i = 1
        while candidate_path in self.upload_paths \
        or os.path.exists(candidate_path):
          candidate_path = '{}.{:d}'.format(path, i)
          i += 1
        self.upload_paths.add(candidate_path)
        return candidate_path



  def release_upload_path(self, handler, path):
    '''
    Release an upload path.
    '''
    with self.upload_lock:
      try:
        self.upload_paths.remove(path)
      except KeyError:
        self.log_error('attemped to release unreserved path')



########################### QuickserveRequestHandler ###########################
class QuickserveRequestHandler(BaseHTTPSRequestHandler):
  '''
  Quickserve request handler.
  '''

  def version_string(self):
    return VERSION_STRING



  def parse_path(self):
    self.url_data = urllib.parse.urlsplit(self.path)
    self.url_path = serverpath_from_uripath(self.url_data.path)
    self.url_qs = urllib.parse.parse_qs(self.url_data.query)
    if 'mimetype' not in self.url_qs:
      self.url_qs['mimetype'] = [self.server.options.default_mimetype]




  def unparse_path(self, path=None, page=None, extra_qs=None, ignored_qs=None):
    qs = dict(self.url_qs)
    try:
      for q in ignored_qs:
        del qs[q]
    except (KeyError, TypeError):
      pass
    try:
      qs.update(extra_qs)
    except TypeError:
      pass
    try:
      if self.server.options.default_mimetype in qs['mimetype']:
        del qs['mimetype']
    except KeyError:
      pass
    if page is not None:
      qs['page'] = [page]
    elif page == '':
      try:
        del qs['page']
      except KeyError:
        pass
    if path is None:
      path = self.url_data.path
    query_string = unparse_qs(qs)
    return '{}?{}'.format(path, query_string)



  def do_authenticated_GET(self):
    self.do_authenticated_GET_or_HEAD()



  def do_authenticated_HEAD(self):
    self.do_authenticated_GET_or_HEAD()



  def use_index(self):
    '''
    Return a boolean value to indicate if an index page should be used for a
    directory request.
    '''
    try:
      return (
        self.server.options.index \
        and self.url_qs['mimetype'][0] == DEFAULT_MIMETYPE
      )
    except AttributeError:
      return False



  def handle_custom(self):
    try:
      page_gen = self.server.page_generators[self.url_qs['mimetype'][0]]
    except KeyError:
      return None

    try:
      if self.url_qs['page'] == ['upload']:
        upload_count = max(1, int(self.url_qs['count'][0]))
        upload_count = min(upload_count, self.server.MAX_UPLOAD_COUNT)
        if self.server.options.upload_dir:
          return page_gen.send_upload_page(self, upload_count)
        else:
          self.send_error(503)
          return
    except KeyError:
      pass
    except (IndexError, ValueError) as e:
      raise QuickserveError(str(e))

    return page_gen



  def handle_unresolved(self):
    return False



  def do_authenticated_GET_or_HEAD(self, extend_resolved=None):
    self.parse_path()

    page_gen = self.handle_custom()
    if not page_gen:
      return self.send_error(404)

    resolved = self.server.resolve_path(self.url_path)
    if resolved is None:
      if not self.handle_unresolved():
        self.send_error(404)
    elif isinstance(resolved, str):
      self.transfer_file(resolved)
    elif self.url_data.path[-1] != '/':
      url_data = self.url_data[:2] + (self.url_data.path + '/',) + self.url_data[3:]
      self.redirect(location=urllib.parse.urlunsplit(url_data))
    # Tar-mediated directory transfer.
    elif 'tar' in self.url_qs and self.server.options.tar is not None:
      compression = self.url_qs['tar'][0]
      try:
        if compression not in self.server.options.tar:
          compression = self.server.options.tar[0]
      except (TypeError, IndexError):
        compression = None
      localpath = self.server.resolve_path(self.url_path, dir_listings=False)
      def hide_path(ti_path):
        root = os.path.dirname(self.url_path)
        ti_url_path = os.path.join(root, ti_path)
        return self.server.hide_path(ti_url_path)

      dpaths = self.server.paths.get(self.url_path.lstrip('/'), (localpath,))

      self.transfer_directory(
        dpaths,
        os.path.basename(self.url_path),
        include_body=True,
        compression=compression,
        hide_path=hide_path
      )
    elif self.use_index():
      index_path = self.server.resolve_path(
        urllib.parse.urljoin(
          self.url_data.path,
          self.server.options.index
        )
      )
      if index_path:
        self.transfer_file(index_path)
      else:
        if extend_resolved is not None:
          resolved = extend_resolved(resolved)
        page_gen.send_directory_listing(self, resolved)
    else:
      if extend_resolved is not None:
        resolved = extend_resolved(resolved)
      page_gen.send_directory_listing(self, resolved)



  def do_authenticated_POST(self):
    if not self.server.options.upload_dir:
      self.send_error(405)
      return

    self.parse_path()

    # This originally used cgi.FieldStorage but the creation of temporary
    # files is sub-optimal. Subclassing and overriding the make_file method
    # did not work for multipart form data because the resulting list used
    # FieldStorage objects instead of the subclassed object. Rather than hack
    # my way through the module to get subclasses working I decided it would
    # be easier to just implement my own multipart form parser.

    try:
      content_type = self.headers['Content-Type'].strip()
    except KeyError:
      self.log_error('no Content-Type in headers')
      self.send_error(400)
      return

    try:
      content_type, boundary = content_type.split(';', 1)
      content_type = content_type.rstrip()
      boundary = boundary.split('=', 1)[1].lstrip().encode('UTF-8')
    except ValueError:
      self.send_error(501)
      return

    final_boundary = boundary + b'--'
    boundary = b'--' + boundary
    final_boundary = boundary + b'--'
    boundary += b'\r\n'
    final_boundary += b'\r\n'
    boundary_size = len(boundary)
    final_boundary_size = boundary_size + 2
    while self.rfile.readline(boundary_size) != boundary:
      pass

    chunk = None
    total_size = 0
    while chunk != final_boundary:
      form_data = dict()
      for line in self.rfile:
        if line == b'\r\n':
          break
        else:
          name, value = line.rstrip(b'\r\n').split(b':')
          if name == b'Content-Disposition':
            values = value.lstrip(b' \t').split(b';')
            if values[0] == b'form-data':
              for field in values[1:]:
                n, v = field.split(b'=', 1)
                n = n.strip()
                v = v.strip(b' \t"')
                form_data[n] = v

      # input error
      if not form_data:
        self.log_error('missing form data')
        self.send_error(400)
        return

      try:
        # basename prevents escaping the upload directory, although this
        # may already be done before the name is passed to the handler
        filename = os.path.basename(form_data[b'filename']).decode()
        if not filename:
          chunk = self.rfile.readline(final_boundary_size)
          while chunk != boundary and chunk != final_boundary:
            chunk = self.rfile.readline(final_boundary_size)
          continue

      except KeyError:
        self.log_error('missing filename')
        self.send_error(400)
        return

      output_path = self.server.get_upload_path(self, filename)
      size = 0
      with open(output_path, 'wb') as f:
        try:
          # +2 because last boundary is suffixed with b'--'
          chunk_size = max(boundary_size + 2, f._CHUNK_SIZE)
        except AttributeError:
          chunk_size = DEFAULT_CHUNK_SIZE

        chunk = self.rfile.readline(chunk_size)
        while chunk and chunk != boundary and chunk != final_boundary:
          bytes = f.write(chunk)
          size += bytes
          total_size += bytes
          chunk = self.rfile.readline(chunk_size)
        # Truncate final b'\r\n'
        f.seek(-2, os.SEEK_END)
        f.truncate()

      # Remove empty files.
      if size == 0:
        os.unlink(path)
      else:
        self.log_message('uploaded {} ({})'.format(
          os.path.basename(output_path),
          format_size(size),
        ))

      self.server.release_upload_path(self, output_path)

      # Remove truncated files.
      if chunk != boundary and chunk != final_boundary:
        os.unlink(output_path)
        self.log_error('truncated file')
        self.send_error(400)
        return

    self.log_message('total upload: {}'.format(format_size(total_size)))
    url = self.unparse_path()
    self.redirect(location=url, status_code=303, message='Upload successful.')



############################### Argument Parsing ###############################

def add_Quickserve_argparse_groups(parser):

  download_options = parser.add_argument_group(
    title="File Download Options"
  )

  download_options.add_argument(
    '--root', metavar='<directory path>',
    help='If given then the directory will be treated as the root of the server and all other paths will be ignored. This is useful for testing static websites. Similar and more complicated effects can be achieved using a JSON filelist.',
  )

  download_options.add_argument(
    '-f', '--filelist', metavar='<filepath>',
    help='A file to specify what to share on the server. If it is a flat plaintext file then each line will be treated as though it had been passed on the command line. If it is a JSON file then it should be a map of server paths to either single files or lists of directories. The contents of each directory in the list will appear as a single directory on the server.'
  )

  download_options.add_argument(
    '--filter', dest='filters', metavar='<ix><regex>', action='append', default=[],
    help='Regular expressions to filter paths that appear on the server. These will be applied in order when determining which files to share.'
  )

  download_options.add_argument(
    '--filterlist', metavar='<filepath>',
    help='A file consisting of filter expressions on each line. The file will be reloaded if it is modified.'
  )

  download_options.add_argument(
    '--show-hidden', action='store_true',
    help='Share hidden files and directories.'
  )

  download_options.add_argument(
    '--tar', nargs='+', choices=TAR_COMPRESSIONS,
    help='Enable directories to be transfered as optionally compressed tar archives. This option accepts the compression types to enable.'
  )



  upload_options = parser.add_argument_group(
    title="File Upload Options"
  )

  upload_options.add_argument(
    '--upload', dest='upload_dir', metavar='<filepath>',
    help='Enable uploads and save uploaded files in given directory.'
  )
  upload_options.add_argument(
    '--allow-overwrite', action='store_true',
    help='Allow uploaded files to overwrite existing files in upload directory.'
  )



  content_options = parser.add_argument_group(
    title="Content Options"
  )

  content_options.add_argument(
    '--motd', metavar='<filepath>',
    help='The MOTD message to display on the server. The file will be reloaded if it is updated.'
  )

  content_options.add_argument(
    '--index', metavar='<filename>',
    help='The name of the index page to display (if present) when a directory is requested.'
  )

  return parser






##################################### Main #####################################
def main(args=None):
  parser = argparse.ArgumentParser(
    description='%(prog)s - a simple HTTP server for quickly sharing files',
  )
  parser.add_argument(
    'paths', metavar='<filepath>', nargs='*',
    help='The files and directories to share. These will appear with the same name in server root. Use the filelist option for more advanced features.',
  )
  parser = add_Quickserve_argparse_groups(parser)
  parser = add_common_argparse_groups(parser)
  parser = add_HTTPS_argparse_groups(parser)
  args = parser.parse_args(args)

  address = (args.address, args.port)

  page_generators = dict()
  for mimetype, pagegen in DEFAULT_PAGE_GENERATORS.items():
    page_generators[mimetype] = pagegen()
  args.default_mimetype = DEFAULT_MIMETYPE

  handler = QuickserveRequestHandler
  server = QuickserveServer(
    address,
    handler,
    args,
    page_generators,
  )
  print(server)
  print("Press ctrl+C to exit.")
  server.serve_forever()



if __name__ == '__main__':
  configure_logging()
  run(main)
