#!/usr/bin/python3

import os
import stat
import errno
import fuse
import sys
from datetime import datetime
from fuse import Fuse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import json

fuse.fuse_python_api = (0, 2)

# Key generation function
def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

# AES Encryption/Decryption functions
class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def decrypt(self, encrypted_data):
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

class FileData():
    def __init__(self, contents: bytes = b'', cipher: AESCipher = None):
        self.cipher = cipher
        self.contents = self.encrypt(contents) if contents else b''
        self.stat = FileStat()
        self.stat.st_size = len(contents)
        self.stat.st_ctime = FileStat.epoch_now()
        self.stat.st_mtime = FileStat.epoch_now()

    def encrypt(self, data):
        return self.cipher.encrypt(data) if self.cipher else data

    def decrypt(self):
        return self.cipher.decrypt(self.contents) if self.cipher else self.contents

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

class EncryptedFS(Fuse):

    def __init__(self, storage_path, cipher):
        super().__init__()
        self.storage_path = storage_path
        self.cipher = cipher
        self.file_data = {}

        if not os.path.exists(storage_path):
            os.makedirs(storage_path)
            self.create_filesystem()
        else:
            self.load_filesystem()

    def create_filesystem(self):
        """Initialize a new encrypted filesystem structure."""
        print("Creating a new encrypted filesystem.")
        self.file_data = {
            "welcome.txt": FileData(b"Welcome to your encrypted filesystem!", self.cipher)
        }
        self.save_filesystem()

    def load_filesystem(self):
        """Load the filesystem from the storage path."""
        print("Loading existing encrypted filesystem.")
        for filename in os.listdir(self.storage_path):
            if filename.endswith('.meta'):
                filepath = os.path.join(self.storage_path, filename)
                with open(filepath, 'r') as meta_file:
                    metadata = json.load(meta_file)
                data_path = filepath.replace('.meta', '.data')
                if os.path.exists(data_path):
                    with open(data_path, 'rb') as data_file:
                        encrypted_data = data_file.read()
                    contents = self.cipher.decrypt(encrypted_data)
                    file = FileData(contents, self.cipher)
                    file.stat.st_size = metadata['st_size']
                    file.stat.st_mode = metadata['st_mode']
                    file.stat.st_ctime = metadata['st_ctime']
                    file.stat.st_mtime = metadata['st_mtime']
                    file.stat.st_atime = metadata['st_atime']
                    self.file_data[filename.replace('.meta', '')] = file

    def save_filesystem(self):
        """Persist the filesystem to disk."""
        for filename, file in self.file_data.items():
            metadata = {
                'st_size': file.stat.st_size,
                'st_mode': file.stat.st_mode,
                'st_ctime': file.stat.st_ctime,
                'st_mtime': file.stat.st_mtime,
                'st_atime': file.stat.st_atime
            }
            meta_path = os.path.join(self.storage_path, filename + '.meta')
            with open(meta_path, 'w') as meta_file:
                json.dump(metadata, meta_file)
            data_path = os.path.join(self.storage_path, filename + '.data')
            with open(data_path, 'wb') as data_file:
                data_file.write(file.contents)

    def readdir(self, path: str, offset: int):
        for r in ['.', '..'] + list(self.file_data.keys()):
            yield fuse.Direntry(r)

    def getattr(self, path: str) -> fuse.Stat:
        if path == '/':
            # Root directory attributes
            st = FileStat()
            st.st_mode = stat.S_IFDIR | 0o755  # Directory with 755 permissions
            st.st_nlink = 2
            return st

        filename = path[1:]  # Remove the leading '/'
        if filename in self.file_data:
            # Retrieve the file's stored attributes
            file_stat = self.file_data[filename].stat
            file_stat.st_mode = stat.S_IFREG | 0o644  # Regular file with 644 permissions
            return file_stat

        return -errno.ENOENT


    def read(self, path: str, size: int, offset: int) -> bytes:
        filename = path[1:]
        if filename not in self.file_data:
            return -errno.ENOENT

        self.file_data[filename].upd_access()
        contents = self.file_data[filename].decrypt()
        slen = len(contents)
        if offset < slen:
            if offset + size > slen:
                size = slen - offset
            buf = contents[offset:offset + size]
        else:
            buf = b''

        return buf

    def create(self, path: str, mode: int, flags):
        """Create a new file with given path and permissions."""
        filename = path[1:]  # Strip leading '/'
        
        # Check if file already exists
        if filename in self.file_data:
            raise fuse.FuseOSError(errno.EEXIST)

        # Create new file data with empty content and set mode
        new_file = FileData(b'', self.cipher)
        new_file.stat.st_mode = stat.S_IFREG | mode
        new_file.stat.st_nlink = 1
        self.file_data[filename] = new_file

        # Persist the new file to disk
        self.save_filesystem()

        return 0

    def write(self, path: str, body: bytes, offset: int, flags=None):
        filename = path[1:]

        # If the file does not exist, create it
        if filename not in self.file_data:
            self.create(path, 0o644, flags)  # Default permission mode

        # Attempt to decrypt existing contents, handle if it's empty
        try:
            contents = self.file_data[filename].decrypt()
        except ValueError:
        # If decryption fails due to missing nonce, initialize as empty
            contents = b''
        
        new_content = contents[:offset] + body + contents[offset + len(body):]
        self.file_data[filename].contents = self.file_data[filename].encrypt(new_content)
        self.file_data[filename].stat.st_size = len(new_content)
        self.file_data[filename].upd_modif()
        self.save_filesystem()  # Save changes to disk

        return len(body)
    
# Password and salt for encryption (For demonstration purposes; consider securely storing these)
password = input("Enter password: ")
salt = b"salty_salt"
key = generate_key(password, salt)
cipher = AESCipher(key)

def main():
    if len(sys.argv) < 3:
        print("Usage: {} <mountpoint> <storage_path>".format(sys.argv[0]))
        sys.exit(1)

    mountpoint = sys.argv[1]
    storage_path = sys.argv[2]

    title = 'Encrypted Filesystem Example'
    descr = ("An example of an encrypted FUSE filesystem with AES encryption \n" +
             "for file contents. Allows for creating, reading, and modifying \n" +
             "files, with all data stored in an encrypted storage directory.")

    # Ensure that mountpoint and storage_path are not the same
    if os.path.abspath(mountpoint) == os.path.abspath(storage_path):
        print("Mountpoint and storage path must be different.")
        sys.exit(1)

    server = EncryptedFS(storage_path, cipher)

    # Set additional FUSE options
    server.multithreaded = False

    # Parse the command-line options and run the server
    server.parse([mountpoint], errex=1)
    server.main()

if __name__ == '__main__':
    main()
