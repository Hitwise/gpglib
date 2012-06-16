import bitstring

class ContentParser(object):
    """Delegator to the different content parsers"""
    def __init__(self):
        self.parsers = {}
        self.parse_unknown = Parser()
        
    def consume(self, tag, info):
        parser = self.parsers.get(tag.tag_type, self.parse_unknown)
        bytes = info.bytes
        if tag.body_bit_length:
            # This packet has a defined length, let's only consume those bytes
            bytes = info.bytes.read(tag.body_bit_length * 8)
        return parser.consume(tag, info, bytes)
    
    def add_parser(self, key_id, parser):
        self.parsers[key_id] = parser
    
    def find_parsers(self):
        parsers = (
              (1, PubSessionKeyParser)
            , (9, SymEncryptedParser)
            )
        
        for tag_type, kls in parsers:
            self.add_parser(tag_type, kls())

class Parser(object):
    """Base Parser class"""
    def consume(self, tag, info, bytes):
        raise NotImplementedError("Don't know about tag type %d" % tag.tag_type)

    def parse_mpi(self, bytes):
        # Get the length of the MPI to read in
        raw_mpi_length = bytes.read(2*8).uint
        mpi_length = (raw_mpi_length + 7) / 8
        
        # Read in the MPI bytes and return the resulting hex
        return bytes.read(mpi_length).hex
        
class PubSessionKeyParser(Parser):
    """Parse public session key packet"""
    def consume(self, tag, info, bytes):
        # Version of the packet we're parsing (almost always '3')
        version = bytes.read(8).uint

        # The id of the key used to encrypt the session key
        key_id = bytes.read(8*8).uint

        # The public key algorithm used to encrypt the session key
        key_algo = bytes.read(8).uint

        if key_algo != 1:  # not RSA-encrypted session key
            # TODO: Implement Elgamal
            raise NotImplementedError("Session keys encrypted with public key type '%d' not implemented" % key_algo)

        # Get the key which was used to encrypt the session key
        try:
            key = info.keys[key_id]
        except KeyError:
            raise PGPException("Data was encrypted with RSA key '%d', which was't found" % key_id)

        # Read the encrypted session key
        encrypted_session_key = self.parse_mpi(bytes)
        
        # Decrypt the session key
        session_key = key.decrypt(encrypted_session_key)

        # Give session key to info
        info.public_session_key = bitstring.ConstBitStream(bytes=session_key).uint
        return info.public_session_key
        
class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    def consume(self, tag, info, bytes):
        print bytes.read(tag.body_bit_length)
