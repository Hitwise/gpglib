# coding:spec

from gpglib.structures import EncryptedMessage

from helpers import data

import unittest

describe "decryption with rsa":
    it "works with with small data":
        message = EncryptedMessage(data.get_keys('rsa'))
        self.assertEqual(message.decrypt(data.get_encrypted('small', 'rsa')), data.get_original('small'))

    it "works with big data":
        message = EncryptedMessage(data.get_keys('rsa'))
        self.assertEqual(message.decrypt(data.get_encrypted('big', 'rsa')), data.get_original('big'))
