from Crypto.Cipher import CAST
import bitstring

class ContentParser(object):
    """Delegator to the different content parsers"""
    def __init__(self):
        self.parsers = {}
        self.parse_unknown = Parser()
        
    def consume(self, tag, message, region):
        """
            Find parser given tag.tag_type
            And consume the provided region of data (limited to tag.body_bit_length)
        """
        # Determine what parser to use for this packet
        # Default to self.parse_unknown, which will do some complaining for us
        parser = self.parsers.get(tag.tag_type, self.parse_unknown)
        
        # Limit bytes to consume if this packet has a defined length
        if tag.body_length:
            region = region.read(tag.body_length*8)
        
        # Consume the desired region
        return parser.consume(tag, message, region)
    
    def find_parsers(self):
        """
            Add parsers to this instance of ContentParser
            It's recommended that only one instance of this class is ever generated
            So this setup only has to happen once
        """
        parsers = (
              (1, PubSessionKeyParser)
            , (9, SymEncryptedParser)
            )
        
        for tag_type, kls in parsers:
            self.parsers[tag_type] = kls()

class Parser(object):
    """Base Parser class"""
    def consume(self, tag, message, region):
        raise NotImplementedError("Don't know about tag type %d" % tag.tag_type)

    def parse_mpi(self, region):
        # Get the length of the MPI to read in
        mpi_length = region.read(2*8).uint
        
        # Read in the MPI bytes and return the resulting bitstream
        return region.read(mpi_length)

class PubSessionKeyParser(Parser):
    """Parse public session key packet"""
    def consume(self, tag, message, region):
        # Version of the packet we're parsing (almost always '3')
        version = region.read(8).uint

        # The id of the key used to encrypt the session key
        key_id = region.read(8*8).uint

        # The public key algorithm used to encrypt the session key
        key_algo = region.read(8).uint

        if key_algo != 1:  # not RSA-encrypted session key
            # TODO: Implement Elgamal
            raise NotImplementedError("Session keys encrypted with public key type '%d' not implemented" % key_algo)

        # Get the key which was used to encrypt the session key
        try:
            key = message.keys[key_id]
        except KeyError:
            raise PGPException("Data was encrypted with RSA key '%d', which was't found" % key_id)

        # Read the encrypted session key
        encrypted_session_key = self.parse_mpi(region).bytes
        
        # Decrypt the session key
        session_key = key.decrypt(encrypted_session_key)

        # Return the session key
        return {
            'session_key': session_key,
        }
        
class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    def consume(self, tag, message, region, session_key):
        iv_len = 8*(CAST.block_size+2)
        ciphertext = region.read(region.len - iv_len).bytes
        iv = region.read(iv_len).bytes
        cipher = CAST.new('blahandstuff', CAST.MODE_OPENPGP, iv)
        message.decrypted = cipher.decrypt(ciphertext)
