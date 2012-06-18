import zlib

import bitstring
from Crypto import Random
from Crypto.Cipher import CAST, PKCS1_v1_5
from Crypto.Hash import SHA

import errors

class ContentParser(object):
    """Delegator to the different content parsers"""
    def __init__(self):
        self.parsers = {}
        self.parse_unknown = Parser()
        
    def consume(self, tag, message, region, kwargs):
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
        return parser.consume(tag, message, region, **kwargs)
    
    def find_parsers(self):
        """
            Add parsers to this instance of ContentParser
            It's recommended that only one instance of this class is ever generated
            So this setup only has to happen once
        """
        parsers = (
              (1, PubSessionKeyParser)
            , (8, CompressedParser)
            , (9, SymEncryptedParser)
            , (11, LiteralParser)
            )
        
        for tag_type, kls in parsers:
            self.parsers[tag_type] = kls()

class Parser(object):
    """Base Parser class"""
    def consume(self, tag, message, region):
        raise NotImplementedError("Don't know about tag type %d" % tag.tag_type)

    def parse_mpi(self, region):
        # Get the length of the MPI to read in
        raw_mpi_length = region.read(2*8).uint
        
        # Read in the MPI bytes and return the resulting bitstream
        mpi_length = (raw_mpi_length + 7) / 8
        return region.read(mpi_length*8)

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
        
        # The encrypted session key is EME-PKCS1-encoded (as described in section
        # 13.1 of the RFC). The sentinel value is generated for crypto reasons,
        # and it is insecure to directly compare it to the output. We must only ever
        # compare the checksum of the resulting key.
        pkcs = PKCS1_v1_5.new(key)

        # Generate the sentinel value (19 is the exact length of a valid decrypted
        # passphrase)
        sentinel = Random.new().read(19)

        # The size of the key in bytes
        key_size = (key.size() + 1) / 8

        # Pad the key with zero's to the left until it's `key_size` bytes long
        encrypted_session_key = encrypted_session_key.rjust(key_size, '\xff')

        # Decrypt and decode the session key
        decrypted = pkcs.decrypt(encrypted_session_key, sentinel)
        padded_session_key = bitstring.ConstBitStream(bytes=decrypted)

        # The algorithm used to encrypt the message is the first byte
        algo = padded_session_key.read(8).uint

        # The session key is the next 16 bytes
        session_key = padded_session_key.read(16*8).bytes

        # The checksum is the last two bytes
        checksum = padded_session_key.read(2*8).uint

        # Generate a checksum from the session_key (section 5.1 in the RFC). This
        # involves summing up all the bytes of the session key and `mod`ing it
        # by 65536.
        generated_checksum = sum(ord(i) for i in session_key) % 65536

        # Compare the checksums and throw an error if they don't match
        if checksum != generated_checksum:
            raise errors.PGPException("The decrypted session key was invalid (checksums didn't match)")

        # Pass the session key bytes and the algorithm used on to the next parser
        return {
            'algo': algo,
            'session_key': session_key,
        }

class CompressedParser(object):
    """Parse compressed packets"""
    def consume(self, tag, message, region):
        # Get the compression algorithm used
        algo = region.read(8).uint

        if algo != 1:  # we only support ZIP compression for now
            raise NotImplementedError("Compression type '%d' not supported" % algo)

        # Use zlib to decompress the packet. The -13 at the end is the window size.
        # It says to ignore the zlib header (because it's negative) and that the
        # data is compressed with up to 15 bits of compression.
        uncompressed = zlib.decompress(region.read('bytes'), -15)

        # Parse the inner packet and return it
        return message.decrypt(uncompressed)

class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    # Mapping of PGP encryption algorithm types to a PyCrypto module which implements
    # that particular algorithm
    ENCRYPTION_ALGORITHMS = {
        3: CAST,  # CAST5
    }

    def consume(self, tag, message, region, algo, session_key):
        # Get the encryption algorithm used
        try:
            cipher = self.ENCRYPTION_ALGORITHMS[algo]
        except KeyError:
            raise NotImplementedError("Symmetric encryption type '%d' hasn't been implemented" % algo)

        # Handy alias for the encryption algo's block size
        block_size = cipher.block_size

        # Find out the length of the IV
        iv_len = block_size + 2

        # Read in the encrypted IV
        iv = region.read(8*iv_len).bytes

        # The ciphertext is what's left in `region`
        ciphertext = region.read('bytes')

        # Build the cipher object from the session key and the IV
        decryptor = cipher.new(session_key, cipher.MODE_OPENPGP, iv)

        # Decrypt the ciphertext
        decrypted = decryptor.decrypt(ciphertext)

        # Parse the inner packet and return it
        return message.decrypt(decrypted)

class LiteralParser(object):
    """No-op parser that sets the given data onto `message`"""
    def consume(self, tag, message, region):
        message.data = region.bytes
