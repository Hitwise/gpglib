from collections import namedtuple

# Information obtained from an OpenPGP header
Tag = namedtuple('Tag', ('version', 'tag_type', 'body_bit_length'))

class Info(object):
    """
        Class to hold:
            * keys
            * Bytes of original data
            * Results form decrypt process
    """
    def __init__(self, keys, bytes):
        self.keys = keys
        self.bytes = bytes
