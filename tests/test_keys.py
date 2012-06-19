# coding: spec

from gpglib.structures import SecretKey
from helpers import data

import unittest
import nose

describe "Consuming private keys":
    it "successfully consumes a private key":
        secret_key = SecretKey()
        ret = secret_key.consume(data.get_pgp_key('secret'))
        print secret_key.consumed_tags
        assert ret
