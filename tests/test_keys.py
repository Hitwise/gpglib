# coding: spec

from gpglib.structures import SecretKey
from helpers import data

import unittest
import nose

describe "Consuming private keys":
    it "successfully consumes a private key":
        secret_key = SecretKey()
        #assert secret_key.consume(data.get_pgp_key('secret'))
        #secret_key.consume(open('/home/david/Code/pipe-dream/pipe_dream/private.gpg').read())
        secret_key.consume(open('/home/david/Code/gpglib/mrapp.dev.gpg').read())
