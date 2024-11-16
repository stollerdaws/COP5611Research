#!/usr/bin/python3

import os
import stat
import errno
import fuse
import sys
import time
import random
import string
import logging
from datetime import datetime
from fuse import Fuse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import json
from quantcrypt.cipher import Krypton
# Create a logger
logger = logging.getLogger()  # Root logger
logger.setLevel(logging.DEBUG)  # Set the global log level

# Create a FileHandler to write logs to a file
file_handler = logging.FileHandler('fuse_debug.log')
file_handler.setLevel(logging.DEBUG)  # Set log level for this handler

# Create a Formatter for the log messages
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)  # Attach formatter to the handler

# Add the FileHandler to the logger
logger.addHandler(file_handler)

# Optional: Add a console handler to see logs in the terminal (for debugging during development)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Example logging calls
logger.debug("This is a debug message")
logger.info("This is an info message")
logger.error("This is an error message")
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
            logging.error(f"Decryption failed: {e}")
            raise e

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
                json.dump(metadata, meta_file)  # This should now work correctly
            data_path = os.path.join(self.storage_path, filename + '.data')
            with open(data_path, 'wb') as data_file:
                data_file.write(file.contents)


    def readdir(self, path: str, offset: int):
        #logging.debug(f"readdir called for path: {path}, offset: {offset}")
        for r in ['.', '..'] + list(self.file_data.keys()):
            yield fuse.Direntry(r)

    def getattr(self, path: str) -> fuse.Stat:
        #logging.debug(f"getattr called for path: {path}")
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

    def setattr(self, path, attr, fh=None):
        logging.debug(f"setattr called: path={path}, attr={attr}")
        filename = path.lstrip("/")
        if filename not in self.file_data:
            logging.error(f"setattr: file not found: {filename}")
            return -errno.ENOENT

        file_stat = self.file_data[filename].stat

        # Handle truncation (st_size)
        if 'st_size' in attr:
            new_size = attr['st_size']
            logging.debug(f"Truncating {filename} to size {new_size}")
            current_content = self.file_data[filename].decrypt()
            truncated_content = current_content[:new_size].ljust(new_size, b'\x00')  # Pad with null bytes if needed
            self.file_data[filename].contents = self.file_data[filename].encrypt(truncated_content)
            file_stat.st_size = new_size

        # Handle mode changes (st_mode)
        if 'st_mode' in attr:
            file_stat.st_mode = attr['st_mode']

        # Handle access and modification times
        if 'st_atime' in attr:
            file_stat.st_atime = attr['st_atime']
        if 'st_mtime' in attr:
            file_stat.st_mtime = attr['st_mtime']

        self.save_filesystem()
        logging.info(f"setattr updated attributes for {filename}")
        return 0



    def utimens(self, path, ts_acc, ts_mod):
        logging.debug(f"utimens called: path={path}, ts_acc={ts_acc}, ts_mod={ts_mod}")

        # Remove leading '/' from path
        filename = path.lstrip("/")

        if filename not in self.file_data:
            logging.error(f"File not found for utimens: {filename}")
            raise fuse.FuseOSError(errno.ENOENT)

        # Convert Timespec to float (seconds since epoch)
        atime = ts_acc.tv_sec + ts_acc.tv_nsec / 1e9
        mtime = ts_mod.tv_sec + ts_mod.tv_nsec / 1e9

        # Update access and modification times
        file_stat = self.file_data[filename].stat
        file_stat.st_atime = atime
        file_stat.st_mtime = mtime

        # Persist the updated metadata
        self.save_filesystem()
        logging.info(f"Updated times for {filename}: atime={atime}, mtime={mtime}")
        return 0

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
        logging.debug(f"create called for path: {path}, mode: {oct(mode)}, flags: {flags}")
        filename = path[1:]  # Remove leading '/'
        if filename not in self.file_data:
            new_file = FileData(b'', self.cipher)
            new_file.stat.st_mode = stat.S_IFREG | mode
            new_file.stat.st_nlink = 1
            self.file_data[filename] = new_file
            self.save_filesystem()
        return 0
    def utime(self, path, times):
        return self.utimens(path, times)


    def write(self, path, data, offset, fh=None):
        logging.debug(f"write called for path: {path}, offset: {offset}, data length: {len(data)}")
        filename = path.lstrip("/")

        if filename not in self.file_data:
            logging.error(f"write: file not found: {filename}")
            return -errno.ENOENT
        # Decrypt the current content
        logging.debug(f'current content: {self.file_data[filename].contents}')
        if self.file_data[filename].contents == b'':   
            current_content = b''
        else:
            try:
                current_content = self.file_data[filename].decrypt()
                if isinstance(current_content, Exception):
                    raise current_content  # Raise the exception if decryption failed
            except Exception as e:
                logging.error(f"Decryption failed for {filename}: {e}")
                return -errno.EIO  # Input/output error

        # Insert the new data at the specified offset
        new_content = current_content[:offset] + data + current_content[offset + len(data):]

        # Encrypt and save the new content
        self.file_data[filename].contents = self.file_data[filename].encrypt(new_content)
        self.file_data[filename].stat.st_size = len(new_content)
        self.file_data[filename].upd_modif()
        self.save_filesystem()

        logging.info(f"Write successful for {filename}: {len(data)} bytes written")
        return len(data)  # Return the number of bytes written

    def unlink(self, path: str):
        """
        Remove a file from the encrypted filesystem.
        """
        logging.debug(f"unlink called for path: {path}")
        filename = path.lstrip("/")  # Remove leading '/'
        
        if filename not in self.file_data:
            logging.error(f"unlink: file not found: {filename}")
            return -errno.ENOENT

        # Remove the file from in-memory data structure
        del self.file_data[filename]
        logging.info(f"File {filename} removed from memory.")

        # Delete the corresponding files from disk
        meta_path = os.path.join(self.storage_path, filename + '.meta')
        data_path = os.path.join(self.storage_path, filename + '.data')
        
        if os.path.exists(meta_path):
            os.remove(meta_path)
            logging.info(f"Metadata file {meta_path} deleted.")
        else:
            logging.warning(f"Metadata file {meta_path} does not exist.")

        if os.path.exists(data_path):
            os.remove(data_path)
            logging.info(f"Data file {data_path} deleted.")
        else:
            logging.warning(f"Data file {data_path} does not exist.")
        
        return 0


    
# Password and salt for encryption (For demonstration purposes; consider securely storing these)

def main():
    if len(sys.argv) < 3:
        print("Usage: {} <mountpoint> <storage_path>".format(sys.argv[0]))
        sys.exit(1)

    mountpoint = sys.argv[1]
    storage_path = sys.argv[2]
    password = sys.argv[3]

    cipher = KryptonCipher(password)
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
    server.fuse_args.add('debug')
    # Parse the command-line options and run the server
    server.parse([mountpoint], errex=1)
    logging.info(f"Starting FUSE server at mountpoint: {mountpoint}")
    server.main()
    logging.info("FUSE server stopped.")

if __name__ == '__main__':
    main()
