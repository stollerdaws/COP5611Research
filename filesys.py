#!/usr/bin/python3
#
# Heavily based on Andrew Straw's (<strawman@astraw.com>) code from 2006.
#
# Distributed under the terms of the GNU LGPL 2.1 or, at your option,
# any newer

import os, stat, errno, fuse, sys
from datetime import datetime
from fuse import Fuse

fuse.fuse_python_api = (0, 2)

class FileData():
    def __init__(self, contents:bytes = b''):
        self.contents = contents
        self.stat = FileStat()
        self.stat.st_size = len(contents)
        self.stat.st_ctime = FileStat.epoch_now()
        self.stat.st_mtime = FileStat.epoch_now()

    def upd_access(self):
        self.stat.st_atime = FileStat.epoch_now()

    def upd_modif(self):
        self.stat.st_mtime = FileStat.epoch_now()

class FileStat(fuse.Stat):
    @classmethod
    def epoch_now(cls):
        return float(datetime.now().strftime('%s'))

    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = os.getuid()
        self.st_gid = os.getgid()
        self.st_size = 0
        self.st_atime = FileStat.epoch_now()
        self.st_mtime = FileStat.epoch_now()
        self.st_ctime = FileStat.epoch_now()

class WithDateHandlingFS(Fuse):

    def readdir(self, path: str, offset: int):
        for r in [ '.', '..' ] + list(file_data.keys()):
            yield fuse.Direntry(r)

    def getattr(self, path: str) -> fuse.Stat:
        if path == '/':
            st = FileStat()
            st.st_mode = stat.S_IFDIR | 0o555
            st.st_nlink = 2
            return st

        for filename in file_data.keys():
            if path == "/" + filename:
                st = file_data[filename].stat
                st.st_mode = stat.S_IFREG | 0o644
                st.st_nlink = 1
                st.st_size = len(file_data[filename].contents)
                return st

        return -errno.ENOENT

    def read(self, path: str, size: int, offset: int) -> bytes:
        filename = path[1:]
        found = False
        contents = None

        file_data[filename].upd_access

        for filename in file_data.keys():
            if path == '/' + filename:
                found = True
                contents = file_data[filename].contents

        if not found:
            return -errno.ENOENT

        slen = len(contents)
        if offset < slen:
            if offset + size > slen:
                size = slen - offset
            buf = contents[offset:offset+size]
        else:
            buf = b''

        return buf

    def truncate(self, path: str, length: int):
        filename = path[1:]
        filesize = file_data[filename].stat.st_size
        contents = file_data[filename].contents

        if filesize < length:
            contents += bytearray(b'\x00' * (length - filesize))
        else:
            contents = file_data[filename].contents[0:length]

        file_data[filename].contents = contents
        file_data[filename].stat.fs_size = len(contents)
        file_data[filename].upd_modif()

    def write(self, path: str, body: bytes, offset: int):
        filename = path[1:]
        contents = file_data[filename].contents
        dest = b''
        if offset > 0:
            dest += contents[0:offset]
        dest += body
        if len(contents) > offset + len(body):
            dest += contents[(offset+len(body)):]

        file_data[filename].contents = dest
        file_data[filename].stat.st_size = len(dest)
        file_data[filename].upd_modif()

        return len(body)

file_data = {
    "static_file": FileData(bytes("Testing", 'utf-8')),
    "static_file_2": FileData(bytes("Testing", 'utf-8')),
    }

def main():
    if len(sys.argv) == 1:
        sys.argv.append('--help')

    title = 'Bones for filesystem'
    descr = ("Presents a static set filenames, with modifiable \n" +
             "contents, and with file information in stat()")

    usage = ("\n\nBeginning FUSE\n  %s: %s\n\n%s\n\n%s" %
             (sys.argv[0], title, descr, fuse.Fuse.fusage))

    server = WithDateHandlingFS(version="%prog " + fuse.__version__,
                                usage=usage,
                                dash_s_do='setsingle')

    server.parse(errex=1)
    server.main()

if __name__ == '__main__':
    main()
