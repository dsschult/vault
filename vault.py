#!/usr/bin/env python3
"""
A simple password manager.

See README.md or docstrings in classes for details.
"""

import os
import sys
import base64
import pickle
import argparse
import getpass
import string
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def random_password(length=24, punctuation=False):
    """
    Generate a random password.

    Args:
        length (int): The password length (default 24).
        punctuation (bool): Whether punctuation is used (default False).

    Returns:
        password (str): The generated password.
    """
    source = string.ascii_letters+string.digits
    if punctuation:
        source += '!@#$%^&*()<>[]{}-+=/'
    r = secrets.SystemRandom()
    return ''.join(r.choice(source) for _ in range(length))


def password_to_key(password, salt):
    """
    Convert a password and salt to a Fernet key.

    From https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

    Args:
        password (bytes): The password to convert.
        salt (bytes): A 16-byte byte string, from a random source.

    Returns:
        key (bytes): A Fernet key (a URL-safe base64-encoded 32-byte byte string).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

#: Salt size in bytes
SALT_SIZE = 32

class Storage(object):
    """
    A Storage object. Encapsulates the cryptographic and storage functions.

    Args:
        filename (str): The path to the vault file.
        master_password (str): The master password for the vault.
    """

    def __init__(self, filename, master_password):
        self.filename = filename
        self.master_password = bytes(master_password.encode('utf-8'))

    def new(self):
        """Set up a new vault, with a new salt"""
        with open(self.filename,'wb') as f:
            f.write(secrets.token_bytes(SALT_SIZE))

    def lock(self, data):
        """
        Lock the vault, storing the contents.

        Args:
            data (object): The contents of the vault, as a python object.
        """
        with open(self.filename,'rb') as f:
            salt = f.read(SALT_SIZE)
        with open(self.filename,'wb') as f:
            f.write(salt)
            fe = Fernet(password_to_key(self.master_password, salt))
            en_data = fe.encrypt(pickle.dumps(data, -1))
            f.write(base64.urlsafe_b64decode(en_data))

    def unlock(self):
        """
        Unlock the vault, returning the contents.

        Returns:
            data (object): The contents of the vault, as a python object.
        """
        with open(self.filename,'rb') as f:
            salt = f.read(SALT_SIZE)
            en_data = base64.urlsafe_b64encode(f.read())
            fe = Fernet(password_to_key(self.master_password, salt))
            return pickle.loads(fe.decrypt(en_data))


class Vault(dict):
    """
    A Vault object, backing an in-memory dict with a Storage object.

    Args:
        filename (str): The path to the vault file.
        master_password (str): The master password for the vault.
    """

    def __init__(self, filename, master_password):
        super(Vault,self).__init__()
        self.storage = Storage(filename, master_password)
        if not os.path.exists(filename):
            self.storage.new()
            self.storage.lock({})
        data = self.storage.unlock()
        if not isinstance(data, dict):
            raise Exception('Bad encryption')
        self.update(data)

    def __setitem__(self, key, value):
        super(Vault,self).__setitem__(key, value)
        self.storage.lock(dict(self))

    def __str__(self):
        if not self:
            return 'No entries'
        else:
            return '\n'.join(str(k) for k in self.keys())

def main():
    desc = 'Store data behind a master password'

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-f', '--filename', type=str,
                        help='The filename to store encrypted data')
    parser.add_argument('--debug', default=False, action='store_true',
                        help='Print debugging information')

    args = parser.parse_args()
    if not args.filename:
        print('Filename required')
        sys.exit(1)

    try:
        mp = getpass.getpass(prompt='Master password:')
    except EOFError:
        sys.exit(1)
    try:
        v = Vault(args.filename,mp)
    except Exception:
        if args.debug:
            raise
        else:
            print('Error reading vault. Bad filename or master password.')
            sys.exit(1)

    banner = '[q]uit, [h]elp, [l]ist, [n]ew [s]tore, [g]et'
    help = """Options:
    q, quit, exit, close        Quit the program.
    h, help                     List these options.
    l, list                     List the key names.
    n, new, generate            Generate a new password.
    s, a, store, add            Store (or overwrite) a new key and password.
    g, get                      Get a password back from the vault."""

    while True:
        print('')
        print(banner)
        try:
            c = input('> ').lower()
        except EOFError:
            break
        if c in ('q', 'quit', 'exit', 'close'):
            break
        elif c in ('h', 'help'):
            print(help)
        elif c in ('l', 'list'):
            print(v)
        elif c in ('n','new', 'generate'):
            kwargs = {}
            l = input('length (enter for default): ')
            if l:
                kwargs['length'] = int(l)
            p = input('punctuation (yes/no): ')
            if p:
                kwargs['punctuation'] = p.lower() in ('y','yes')
            print('password:', random_password(**kwargs))
        elif c in ('s', 'store', 'a', 'add'):
            k = input('key: ')
            v[k] = getpass.getpass(prompt='password: ')
        elif c in ('g', 'get'):
            k = input('key: ')
            if k not in v:
                print('key does not exist')
            else:
                print('password:', v[k])
        else:
            print('Bad command')
    print('')

if __name__ == '__main__':
    main()
