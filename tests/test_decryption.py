# coding:spec

from gpglib.structures import EncryptedMessage

from helpers import data

import unittest

describe "decryption":
    it "works with with small data":
        message = EncryptedMessage(data.get_keys())
        self.assertEqual(message.decrypt(data.get_encrypted('small')), data.get_original('small'))

    it "works with big data":
        message = EncryptedMessage(data.get_keys())
        self.assertEqual(message.decrypt(data.get_encrypted('big')), data.get_original('big'))
