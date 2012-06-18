# coding:spec

from gpglib.structures import Message

from helpers import data

import unittest

describe "decryption":
    it "works with with small data":
        message = Message(data.get_rsa_keys(), data.get_encrypted('small'))
        self.assertEqual(message.decrypt(), data.get_original('small'))

    it "works with big data":
        message = Message(data.get_rsa_keys(), data.get_encrypted('big'))
        self.assertEqual(message.decrypt(), data.get_original('big'))
