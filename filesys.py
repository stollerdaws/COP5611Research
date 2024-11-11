#!/usr/bin/python3

import os
import stat
import errno
import fuse
import sys
import time
import random
import string
from datetime import datetime
from fuse import Fuse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import json
from quantcrypt.cipher import Krypton

fuse.fuse_python_api = (0, 2)

# Key generation function
def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def pad_password(password: str, length: int = 64) -> str:
    if len(password) >= length:
        return password[:length]  # Truncate if password is already longer than the specified length
    padding_length = length - len(password)
    padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_length))
    return password + padding

# AES Encryption/Decryption functions
class KryptonCipher():
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = Krypton(self.key)
        cipher.begin_encryption()
        ciphertext = cipher.encrypt(data)
        verify_dp = cipher.finish_encryption()
        return ciphertext + verify_dp

    def decrypt(self, encrypted_data):
        cipher = Krypton(self.key)
        tag = encrypted_data[-160:]
        cipher.begin_decryption(tag)
        plaintext = cipher.decrypt(encrypted_data[:-160])
        cipher.finish_decryption()
        if plaintext is None:
            raise ValueError("Decryption failed: Invalid tag")
        return plaintext

class FileData():
    def __init__(self, contents: bytes = b'', cipher: KryptonCipher = None):
        self.cipher = cipher
        self.contents = self.cipher.encrypt(contents) if contents else b''
        self.stat = FileStat()
        self.stat.st_size = len(contents)
        self.stat.st_ctime = FileStat.epoch_now()
        self.stat.st_mtime = FileStat.epoch_now()

    def encrypt(self, data):
        return self.cipher.encrypt(data) if self.cipher else data

    def decrypt(self):
        try:
            return self.cipher.decrypt(self.contents) if self.cipher else self.contents
        except ValueError as e:
            return e
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

        return fuse.FuseOSError(errno.ENOENT)

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
        filename = path[1:]  # Remove leading '/'
        
        # Create a new file with default content if it does not exist
        if filename not in self.file_data:
            new_file = FileData(b'', self.cipher)
            new_file.stat.st_mode = stat.S_IFREG | mode
            new_file.stat.st_nlink = 1
            new_file.stat.st_size = 0
            now = time.time()
            new_file.stat.st_atime = now
            new_file.stat.st_mtime = now
            self.file_data[filename] = new_file
            self.save_filesystem()
            
        return 0


    def write(self, path: str, data: bytes, offset: int):
        filename = path[1:]

        if filename not in self.file_data:
            raise fuse.FuseOSError(errno.ENOENT)

        # Decrypt current contents or initialize with an empty byte array
        current_content = self.file_data[filename].decrypt() if offset == 0 else b''

        # Insert new content at the correct offset (append or overwrite based on offset)
        new_content = current_content[:offset] + data + current_content[offset + len(data):]

        # Update the encrypted content and file size
        self.file_data[filename].contents = self.file_data[filename].encrypt(new_content)
        self.file_data[filename].stat.st_size = len(new_content)
        self.file_data[filename].upd_modif()
        self.save_filesystem()

        return len(data)  # Return number of bytes written


    
# Password and salt for encryption (For demonstration purposes; consider securely storing these)
password = input("Enter password: ")
padded_password = pad_password(password)
print("Padded password:", padded_password)
cipher = KryptonCipher(padded_password)
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
