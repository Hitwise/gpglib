from Crypto.PublicKey import RSA
import bitstring

from content_parsers import ContentParser
from errors import PGPFormatException
from structures import Tag, Info
import utils

class PacketParser(object):
    def __init__(self, keys):
        # Content parser is stateless
        self.content_parser = ContentParser()
        self.content_parser.find_parsers()
    
    def decrypt(self, data):
        """
            Decrypt provided data
            Done by continually reading in packets untill none left
            Use next_tag to determine information about each packet
            Use content_parser to actually parse the packet
        """
        bytes = bitstring.ConstBitStream(bytes=data)
        info = Info(keys, bytes)
        
        while True:
            tag = self.next_tag(info)
            if info.bytes.len == 0:
                break
            self.content_parser.consume(tag, info)
        return info
    
    def next_tag(self, info):
        """Determine the version, tag_type and body_bit_length of the next packet"""
        # Each tag is the next 8 bytes
        tag = info.bytes.read(8)

        # The left-most bit *MUST* be 1
        if not tag.read(1).uint:
            raise PGPFormatException("The left-most bit of the tag ('%x') was not 1" % tag.uint)

        # The second bit is the version
        version = tag.read(1).uint
        if version == 1:
            return self.next_new_tag(tag, info)
        else:
            return self.next_old_tag(tag, info)
    
    def next_new_tag(self, bytes, info):
        # TODO: Implement the new length format when we find the need to
        raise NotImplementedError("The new PGP length format is not handled yet")
        
    def next_old_tag(self, tag, info):
        """
            6 bytes left to parse in the tag
            Type is the first four
            and length is determined by the two after that
        """
        tag_type = tag.read(4).uint
        length_type = tag.read(2).uint
        
        if length_type == 3:
            raise NotImplementedError("PGP messages with a null length are not yet supported")
            
        # Determine the length of the packet body
        body_bit_length = self.determine_old_body_length(length_type, info.bytes)
        
        # Return the tag
        return Tag(version=0, tag_type=tag_type, body_bit_length=body_bit_length)
    
    def determine_old_body_length(self, length_type, bytes):
        """Determine body length of an old style packet"""
        if length_type == 0:
            # One Octet length
            return utils.read_scalar(1, bytes)
        
        elif length_type == 1:
            # Two Octet length
            return utils.read_scalar(2, bytes)
        
        elif length_type == 2:
            # Four Octet length
            return utils.read_scalar(4, bytes)
        
        else:
            raise NotImplementedError("Sorry, gpglib doesn't know about indeterminate lengths yet...")

if __name__ == '__main__':
    key = RSA.importKey(open('../tests/data/gpg/key.asc').read())
    packet = open('../tests/data/data.dump.gpg').read()

    keys = {
        5524596192824459786: key,
    }

    decryptor = PacketParser(keys)
    decryptor.decrypt(packet)
