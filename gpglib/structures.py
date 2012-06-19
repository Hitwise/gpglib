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
        self._tags = {'tags' : []}
        self._current_tag = None
    
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

        self.subpacket_consumer.consume(self, region)

    ####################
    ### TAG RECORDING
    ####################

    @property
    def consumed_tags(self):
        """Return list of consumed tags"""
        return list(self.tag_numbers(self._tags))

    def start_tag(self, tag):
        """Record the start of a tag"""
        parent = self._tags
        if self._current_tag:
            parent = self._current_tag

        next_tag = {'tags' : [], 'info' : tag, 'parent' : parent}
        self._current_tag = next_tag

        parent['tags'].append(next_tag)

    def end_tag(self):
        """Record that a tag was finished"""
        self._current_tag = self._current_tag['parent']

    def tag_numbers(self, tags):
        """
            Get a list from the heirarchy of recorded tags
            [[tag_type, children], tag_type, tag_type, [tag_type, children]]

            Where the ones of [tag_type, children] have the same list but for it's children
        """
        if tags:
            for tag in tags['tags']:
                tag_type = tag['info'].tag_type
                if tag['tags']:
                    yield [tag_type, list(self.tag_numbers(tag))]
                else:
                    yield tag_type

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
