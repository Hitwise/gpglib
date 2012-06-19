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
           For the first run, region should be the entire file
           For packets that contain other packets, region will be the bytes for just that packet
       
       message.bytes will always be the bytes for the entire message
    """
    def __init__(self, keys):
        # Content parser is stateless
        self.content_parser = ContentParser()
        self.content_parser.find_parsers()
    
    def consume(self, message, region):
        """
            Consume provided region of data
            Done by continually reading in packets untill none left
            Use next_tag to determine information about each packet
            Use content_parser to actually parse the packet
        """
        kwargs = {}
        while region.pos != region.len:
            tag = self.next_tag(region)

            # Pass the results from the previous parser call to the next one
            message.start_tag(tag)
            kwargs = self.content_parser.consume(tag, message, kwargs) or {}
            message.end_tag()
        return message
    
    def next_tag(self, region):
        """Determine the version, tag_type and body_bit_length of the next packet"""
        # Tag information is held by the first 8 bytes
        tag = region.read(8)

        # The left-most bit *MUST* be 1
        if not tag.read(1).uint:
            raise PGPFormatException("The left-most bit of the tag ('%x') was not 1" % tag.uint)

        # The second bit is the version
        # How the tag is parsed changes between the two versions
        version = tag.read(1).uint
        if version == 1:
            # Read the tag type as the next 6 bits
            tag_type = tag.read(6).uint

            return self.parse_new_tag(tag_type, region)
        else:
            return self.parse_old_tag(tag, region)
    
    def parse_new_tag(self, tag_type, region):
        """
            The length of the packet is then determined by the next group of bytes
        """
        # We peek at the next byte to determine what type of length to get
        length_type = region.peek(8).uint
        body_length = self.determine_new_body_length(length_type, region)

        # Determine the body of the packet
        if body_length is not None:
            body = region.read(body_length*8)
        else:
            # Found a partial packet. Add up all the partials to get the entire body
            body_len = 1 << (length_type & 0b11111)

            # Read the specified length of bytes from the body
            body = region.read(body_len*8)

            # See recursion
            body += self.parse_new_tag(tag_type, region).body

        # Return the tag
        return Tag(version=1, tag_type=tag_type, body=body)
        
    def parse_old_tag(self, tag, region):
        """
            6 bits left to parse in the tag
            Type is the first four
            and length is determined by the two after that
        """
        tag_type = tag.read(4).uint
        length_type = tag.read(2).uint
        
        if length_type == 3:  # indeterminate length untill the end of the file
            body_length = None
        else:
            # Determine the length of the packet body
            body_length = self.determine_old_body_length(length_type, region)
        
        # Get body of the packet
        if body_length is not None:
            body = region.read(body_length * 8)
        else:
            body = region.read(region.len - region.pos)

        # Return the tag
        return Tag(version=0, tag_type=tag_type, body=body)
    
    def determine_old_body_length(self, length_type, region):
        """Determine body length of an old style packet"""
        if length_type < 3:
            octet_length = 2**length_type
            return region.read(8*octet_length).uint
        else:
            # indeterminate length untill the end of the file
            return None
    
    def determine_new_body_length(self, length_type, region):
        """
            The first byte (given as length_type and still to be read from region) is used to determine how many to look at
            < 192 = one octet
            > 192 and < 224  = two octet
            == 255 = ignore the 255, and use the next 4 octets
            otherwise it is partial length
        """
        if length_type < 192:
            return region.read(8).uint
        
        elif length_type < 224:
            # TODO: Make this nicer
            return ((region.read(8).uint - 192) << 8) + (region.read(8).uint + 192)
        
        elif length_type == 255:
            # Ignore the first octet (255 just says to look at next 4)
            region.read(8)
            
            # Add up the next four octets
            return region.read(8*4).uint
        
        else:
            # Length_type hasn't been read yet, just peeked
            region.read(8)

            # Return None to specify a partial packet
            return None
