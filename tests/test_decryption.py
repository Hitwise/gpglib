# coding:spec

from gpglib.structures import EncryptedMessage

from helpers import data

import unittest

def create_decryption_check(size, key, cipher):
    """
        Generate a test function to tests a combination of factors for decryption
        * Size of the message
        * Public Key type
        * Cipher used
    """
    def func(self):
        message = EncryptedMessage(data.get_keys(key))
        original = data.get_original(size)
        decrypted = message.decrypt(data.get_encrypted(size, key, cipher))
        self.assertEqual(decrypted, original)

    func.__name__ = "Testing key size=%s, key=%s, cipher=%s" % (size, key, cipher)
    func.__test_name__ = func.__name__
    return func

def generate_funcs():
    """
        Use create_decryption_check to generate test functions
        These are used in TestCase class created below
    """
    args = {}
    for size in ('small', 'big'):
        for key in ('rsa', 'dsa'):
            for cipher in ('cast5', 'aes'):
                tester = create_decryption_check(size, key, cipher)
                args[tester.__name__] = tester
    return args

# The class that holds all the tests
TestDecryption = type("TestDecryption", (unittest.TestCase, ), generate_funcs())
TestDecryption._is_noy_spec = True
