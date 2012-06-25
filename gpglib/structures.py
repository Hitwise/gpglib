from collections import namedtuple
import bitstring

from utils import ValueTracker

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
        self.reset()

    def reset(self):
        self.tags = ValueTracker()
    
    ####################
    ### CONSUMING
    ####################
    
    @property
    def packet_consumer(self):
        """Memoized PacketParser"""
        if not hasattr(self, '_packet_consumer'):
            from packet_parser import PacketParser
            self._packet_consumer = PacketParser()
        return self._packet_consumer
    
    @property
    def subsignature_consumer(self):
        """Memoized SubSignatureParser"""
        if not hasattr(self, '_subsignature_consumer'):
            from packet_parser import SubSignatureParser
            self._subsignature_consumer = SubSignatureParser()
        return self._subsignature_consumer
    
    def consume(self, region):
        """
            Consume a message.
            Region can be specified to handle nested packets
            Otherwise, defaults to the byte stream on the Message object itself

            If a string is passed in as region, it is converted to a bitstream for you
        """
        if isinstance(region, (str, unicode)):
            region = bitstring.ConstBitStream(bytes=region)

        self.packet_consumer.consume(self, region)
    
    def consume_subsignature(self, region):
        """
            Consume subsignature packets
            Region can be specified to handle nested packets
            Otherwise, defaults to the byte stream on the Message object itself

            If a string is passed in as region, it is converted to a bitstream for you
        """
        if isinstance(region, (str, unicode)):
            region = bitstring.ConstBitStream(bytes=region)

        self.subsignature_consumer.consume(self, region)
    
    ####################
    ### ADDING TAGS
    ####################
    
    def start_tag(self, tag):
        """Record start of a new tag"""
        self.tags.start_item(tag)
    
    def end_tag(self):
        """Record end of a new tag"""
        self.tags.end_item()

####################
### ENCRYPTED MESSAGE
####################

class EncryptedMessage(PGPMessage):
    def __init__(self, keys):
        self.keys = keys
        super(EncryptedMessage, self).__init__()

    def reset(self):
        super(EncryptedMessage, self).reset()
        self._plaintext = []
    
    def decrypt(self, region):
        """
            Consume the provided data
            And return the plaintext on the message
        """
        # Reset the plaintext
        self.reset()

        # Consume the stream
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
### KEY
####################

class Key(PGPMessage):
    def __init__(self, passphrase=None):
        self._passphrase = passphrase
        super(Key, self).__init__()

    def reset(self):
        super(Key, self).reset()
        self.keys = ValueTracker()

    @property
    def passphrase(self):
        """Return a function to get the passphrase"""
        if not callable(self._passphrase):
            _passphrase = self._passphrase
            def get_passphrase(message, info):
                return _passphrase
            self._passphrase = get_passphrase
        return self._passphrase
    
    def parse(self, region):
        self.reset()
        self.consume(region)
        return self

    def key_dict(self, keys=None):
        if keys is None:
            keys = self.keys.consumed()

        result = {}
        for key, subkeys in keys:
            result[key['key_id']] = key['key']
            result.update(self.key_dict(subkeys))
        return result
    
    ####################
    ### ADDING KEYS
    ####################
    
    def add_key(self, info):
        """Start a new public key"""
        self.keys.end_item()
        self.keys.start_item(info)
    
    def add_sub_key(self, info):
        """Add a sub public key"""
        self.keys.start_item(info)
