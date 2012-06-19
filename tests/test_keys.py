# coding: spec

from gpglib.structures import Key
from helpers import data

import unittest
import nose

describe "Consuming keys":
    it "successfully consumes a secret key":
        secret_key = Key().parse(data.get_pgp_key('secret'))
        print secret_key.tags.consumed('tag_type')
        print secret_key.secret_keys.consumed(tag=lambda info, key, tag: tag.tag_type)
        assert False
    
    it "successfully consumes a public key":
        public_key = Key().parse(data.get_pgp_key('public'))
        print public_key.tags.consumed('tag_type')
        print public_key.public_keys.consumed(tag=lambda info, key, tag: tag.tag_type)
        assert False
