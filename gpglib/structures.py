from collections import namedtuple
import bitstring

# Information obtained from an OpenPGP header
Tag = namedtuple('Tag', ('version', 'tag_type', 'body_length'))

class Message(object):
    """
        Class to hold details about a message:
            * keys
            * data is the string representing the original data
              It is converted to a bitstream for you
            * Results form decrypt process
    """
    def __init__(self, keys, data):
        self.keys = keys
        self.bytes = bitstring.ConstBitStream(bytes=data)
        self._plaintext = []

    @property
    def plaintext(self):
        """
            Concatenate all plaintext found in the message
            Requires decrypt to have already been called
        """
        return ''.join(self._plaintext)
    
    @property
    def decryptor(self):
        """Memoized PacketParser"""
        if not hasattr(self, '_decryptor'):
            from packet_parser import PacketParser
            self._decryptor = PacketParser(self.keys)
        return self._decryptor
    
    def decrypt(self, region=None):
        """
            Decrypt a message.
            Bytes can be specified to handle nested packets
            Otherwise, defaults to the byte stream on the Message object itself

            If a string is passed in as region, it is converted to a bitstream for you
        """
        if region is None:
            region = self.bytes

        if type(region) in (str, unicode):
            region = bitstring.ConstBitStream(bytes=region)

        self.decryptor.consume(self, region)

    def add_plaintext(self, plaintext):
        """
            More plaintext was found
            I think it's possible to have multiple literalpackets in one pgp message.
            I could be wrong about that....
        """
        self._plaintext.append(plaintext)
