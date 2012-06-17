from Crypto.PublicKey import RSA
import bitstring

from content_parsers import ContentParser
from errors import PGPFormatException
from structures import Tag

class PacketParser(object):
    """
        RFC 4880 Section 4 says that a message is made up of many packets.
        Where a packet consists of a packet header followed by the packet body.
        
        The packet header is made up of::
            * The first 8 bytes, which is referred to as the tag
            * The length of the rest of the packet
        
        This implementation calls the entire packet header a tag
        and will create a structures.Tag to represent it
        
        consume will take in the Message structure and the next region of bytes for consideration
           For the first run, bytes should be the entire file
           For packets that contain other packets, bytes will be the bytes for just that packet
    """
    def __init__(self, keys):
        # Content parser is stateless
        self.content_parser = ContentParser()
        self.content_parser.find_parsers()
    
    def consume(self, message, bytes):
        """
            Consume provided data
            Done by continually reading in packets untill none left
            Use next_tag to determine information about each packet
            Use content_parser to actually parse the packet
        """        
        while True:
            if bytes.pos == bytes.len:
                break
            tag = self.next_tag(bytes)
            self.content_parser.consume(tag, message, bytes)
        return message
    
    def next_tag(self, bytes):
        """Determine the version, tag_type and body_bit_length of the next packet"""
        # Each tag is the next 8 bytes
        tag = bytes.read(8)

        # The left-most bit *MUST* be 1
        if not tag.read(1).uint:
            raise PGPFormatException("The left-most bit of the tag ('%x') was not 1" % tag.uint)

        # The second bit is the version
        version = tag.read(1).uint
        if version == 1:
            return self.next_new_tag(tag, bytes)
        else:
            return self.next_old_tag(tag, bytes)
    
    def next_new_tag(self, tag, bytes):
        """
            6 bits left to parse in the tag
            All 6 bits become the content type
            The length of the packet is then determined by the next group of bytes
        """
        tag_type = tag.read(6).uint
        
        # We peek at the next byte to determine what type of length to get
        length_type = bytes.peek(8).uint
        body_bit_length = self.determine_new_body_length(length_type, bytes)
        
        # Return the tag
        return Tag(version=1, tag_type=tag_type, body_bit_length=body_bit_length)
        
    def next_old_tag(self, tag, bytes):
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
        body_bit_length = self.determine_old_body_length(length_type, bytes)
        
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
