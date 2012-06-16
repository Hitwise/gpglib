from Crypto.PublicKey import RSA
import bitstring

from content_parsers import ContentParser
from errors import PGPFormatException
from structures import Tag, Info

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
    
    def next_new_tag(self, tag, info):
        """
            6 bits left to parse in the tag
            All 6 bits become the content type
            The length of the packet is then determined by the next group of bytes
        """
        tag_type = tag.read(6).uint
        
        # We peek at the next byte to determine what type of length to get
        length_type = info.bytes.peek(8).uint
        body_bit_length = self.determine_new_body_length(length_type, info.bytes)
        
        # Return the tag
        return Tag(version=1, tag_type=tag_type, body_bit_length=body_bit_length)
        
    def next_old_tag(self, tag, info):
        """
            6 bits left to parse in the tag
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
            return bytes.read(8).uint
        
        elif length_type == 1:
            # Two Octet length
            return bytes.read(8*2).uint
        
        elif length_type == 2:
            # Four Octet length
            return bytes.read(8*4).uint
        
        else:
            # Indeterminate length untill the end of the file
            return None
    
    def determine_new_body_length(self, length_type, bytes):
        """
            The first byte (given as length_type, which is still on bytes) is used to determine how many to look at
            < 192 = one octet
            > 192 and < 224  = two octet
            == 255 = ignore the 255, and use the next 4 octets
            otherwise it is partial length
        """
        if length_type < 192:
            return bytes.read(8).uint
        
        elif length_type < 224:
            return bytes.read(8*2).uint
        
        elif length_type == 255:
            # Ignore the first octet (255 just says to look at next 4)
            bytes.read(8)
            
            # Add up the next octets
            return bytes.read(8*4).uint
        
        else:
            raise NotImplementedError("Don't know how to do partial packet length....")

if __name__ == '__main__':
    key = RSA.importKey(open('../tests/data/gpg/key.asc').read())
    packet = open('../tests/data/data.dump.gpg').read()

    keys = {
        5524596192824459786: key,
    }

    decryptor = PacketParser(keys)
    decryptor.decrypt(packet)
