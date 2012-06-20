# coding: spec

from gpglib.structures import Key
from helpers import data

import unittest
import nose

describe "Consuming keys":
    it "successfully consumes a secret key":
        secret_key = Key(passphrase='blahandstuff').parse(data.get_pgp_key('secret'))
        # Parent key
        self.assertIn(4259707814030784140, secret_key.key_dict())
        # Sub-key
        self.assertIn(5524596192824459786, secret_key.key_dict())
    
    it "successfully consumes a public key":
        public_key = Key().parse(data.get_pgp_key('public'))
        # Parent key
        self.assertIn(3166937994423974160, public_key.key_dict())
        # Sub-key
        self.assertIn(11980534847294644458L, public_key.key_dict())
