from collections import namedtuple
import bitstring

# Information obtained from an OpenPGP header
Tag = namedtuple('Tag', ('version', 'tag_type', 'body'))

####################
### BASE MESSAGE
####################

class PGPMessage(object):
    """
        Class to hold details about a pgp message:
        Whether that be keys or encrypted data

        Has method for consuming the data using a PacketParser as message.consume
    """
    def __init__(self):
        self.keys = {}
    
    @property
    def consumer(self):
        """Memoized PacketParser"""
        if not hasattr(self, '_consumer'):
            from packet_parser import PacketParser
            self._consumer = PacketParser(self.keys)
        return self._consumer
    
    def consume(self, region):
        """
            Decrypt a message.
            Bytes can be specified to handle nested packets
            Otherwise, defaults to the byte stream on the Message object itself

            If a string is passed in as region, it is converted to a bitstream for you
        """
        if isinstance(region, (str, unicode)):
            region = bitstring.ConstBitStream(bytes=region)

        self.consumer.consume(self, region)

####################
### ENCRYPTED MESSAGE
####################
class EncryptedMessage(PGPMessage):
    def __init__(self, keys):
        super(EncryptedMessage, self).__init__()
        self.keys = keys
        self._plaintext = []
    
    def decrypt(self, region):
        """
            Consume the provided data
            And return the plaintext on the message
        """
        self.consume(region)
        return self.plaintext

    @property
    def plaintext(self):
        """
            Concatenate all plaintext found in the message
            Requires decrypt to have already been called
        """
        return ''.join(self._plaintext)

    def add_plaintext(self, plaintext):
        """
            More plaintext was found
            I think it's possible to have multiple literalpackets in one pgp message.
            I could be wrong about that....
        """
        self._plaintext.append(plaintext)

####################
### SECRET KEY
####################

class SecretKey(PGPMessage):
    def parse_keys(self, region):
        self.consume(region)
        return self.keys
