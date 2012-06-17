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
    
    @property
    def decryptor(self):
        """Memoized PacketParser"""
        if not hasattr(self, 'decryptor'):
            from packet_parser import PacketParser
            self._decryptor = PacketParser(self.keys)
        return self._decryptor
    
    def decrypt(self, bytes=None):
        """
            Decrypt a message.
            Bytes can be specified to handle nested packets
            Otherwise, defaults to the byte stream on the info object itself
        """
        if bytes is None:
            bytes = self.bytes
        self.decryptor.consume(self, bytes)
