"""Tests for vault.py"""

import os
import base64
import unittest
import tempfile
import shutil
from functools import partial
import string

import vault

class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(partial(shutil.rmtree,self.tmp_dir))

    def test_01_random_password(self):
        a = vault.random_password()
        self.assertEqual(len(a), 24)
        self.assertTrue(all(x not in a for x in string.punctuation))

        # test for repeats
        for _ in range(10000):
            b = vault.random_password()
            self.assertNotEqual(a, b)

        # test length
        a = vault.random_password(length=12)
        self.assertEqual(len(a), 12)

        # test punctuation
        a = vault.random_password(punctuation=True)
        self.assertTrue(any(x in a for x in string.punctuation))

    def test_02_password_to_key(self):
        key = vault.password_to_key(b'blah', b'saltsaltsaltsalt')
        raw_key = base64.urlsafe_b64decode(key)
        try:
            self.assertTrue(isinstance(key, bytes))
            self.assertTrue(isinstance(raw_key, bytes))
            self.assertEqual(len(raw_key), 32)
        except:
            print(key,raw_key,len(raw_key))
            raise

        # test bad password
        try:
            vault.password_to_key('blah', b'saltsaltsaltsalt')
        except Exception:
            pass
        else:
            raise Exception('unicode password should not work')

        # test bad salt
        try:
            vault.password_to_key(b'blah', 'saltsaltsaltsalt')
        except Exception:
            pass
        else:
            raise Exception('unicode salt should not work')

    def test_10_storage_new(self):
        filename = os.path.join(self.tmp_dir, 'test')
        masterpass = 'test_pass'

        s = vault.Storage(filename, masterpass)
        s.new()

        self.assertEqual(os.path.getsize(filename), 16)

    def test_11_storage_lock(self):
        for n in range(3):
            filename = os.path.join(self.tmp_dir, 'test'+str(n))
            masterpass = vault.random_password()
            data = {string.ascii_letters[i]:vault.random_password() for i in range(50)}

            s = vault.Storage(filename, masterpass)
            s.new()
            s.lock(data)
            new_data = s.unlock()
            self.assertEqual(data, new_data)

    def test_20_vault(self):
        filename = os.path.join(self.tmp_dir, 'test')
        masterpass = vault.random_password()

        v = vault.Vault(filename, masterpass)

        self.assertEqual(str(v), 'No entries')

        d = {}
        for i in range(2):
            k = string.ascii_letters[i]
            p = vault.random_password()
            d[k] = p
            v[k] = p

        self.assertEqual(str(v), '\n'.join(d.keys()))
        self.assertEqual(dict(v), d)
        del v

        v2 = vault.Vault(filename, masterpass)
        self.assertEqual(dict(v2), d)

    def test_21_vault(self):
        filename = os.path.join(self.tmp_dir, 'test')
        masterpass = vault.random_password()

        v = vault.Vault(filename, masterpass)

        # a more extensive test
        d = {}
        for i in range(50):
            k = string.ascii_letters[i]
            p = vault.random_password()
            d[k] = p
            v[k] = p

        self.assertEqual(str(v), '\n'.join(d.keys()))
        self.assertEqual(dict(v), d)

        v2 = vault.Vault(filename, masterpass)
        self.assertEqual(dict(v2), d)


if __name__ == '__main__':
    unittest.main()
