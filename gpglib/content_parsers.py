import zlib

import bitstring
from Crypto import Random
from Crypto.Cipher import CAST, PKCS1_v1_5
from Crypto.Hash import SHA

import errors

####################
### DELEGATORS
####################

class ContentParser(object):
    """Delegator to the different content parsers"""
    def __init__(self):
        self.parsers = {}
        self.parse_unknown = self.parser_for_unknown()

        # Instantiate parsers from find_parsers
        # Recommended ContentParser is memoized when created
        for tag_type, kls in self.find_parsers():
            self.parsers[tag_type] = kls()

    def parser_for_unknown(self):
        """Return instantiated parser to handle unknown tags"""
        return Parser()

    def find_parsers(self):
        """Specify lits of [(tag_type, kls), (tag_type, kls), ...] for kls to handle each tag type"""
        raise NotImplemented
        
    def consume(self, tag, message, kwargs):
        """
            Find parser given tag.tag_type
            And consume the body of the tag using correct packet parser
        """
        # Determine what parser to use for this packet
        # Default to self.parse_unknown, which will do some complaining for us
        parser = self.parsers.get(tag.tag_type, self.parse_unknown)
        
        # Consume the desired region
        return parser.consume(tag, message, tag.body, **kwargs)

class PacketContentParser(ContentParser):
    def find_parsers(self):
        """Specifiy parsers"""
        return (
              (1, PubSessionKeyParser)
            , (2, SignatureParser)
            , (5, SecretKeyParser)
            , (6, PublicKeyParser)
            , (7, SecretSubKeyParser)
            , (8, CompressedParser)
            , (9, SymEncryptedParser)
            , (11, LiteralParser)
            , (13, UserIdParser)
            , (14, PublicSubKeyParser)
            )

class SubSignatureContentParser(ContentParser):
    def find_parsers(self):
        """Don't handle any sub signature packets yet"""
        return ()

    def parser_for_unknown(self):
        """Return instantiated parser to handle unknown tags"""
        def consume(parser, tag, message, region, subsignature=None):
            if not subsignature:
                subsignature = {}
            subsignature[tag.tag_type] = region.read('bytes')
            return {'subsignature' : subsignature}

        return type("SignatureParser", (Parser, ), {'consume' : consume})()

####################
### PARSERS
####################

class Parser(object):
    """Base Parser class"""
    def consume(self, tag, message, region):
        raise NotImplementedError("Don't know about tag type %d" % tag.tag_type)

    def only_implemented(self, received, implemented, message):
        if received not in implemented:
            raise NotImplementedError("%s |:| Sorry, haven't implemented value %s. Have only implemented %s." % (self.name, received, message))

    @property
    def name(self):
        return self.__class__.__name__

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
        # TODO: Implement Elgamal
        key_algo = region.read(8).uint
        self.only_implemented(key_algo, (1, ), "session keys implemented with rsa")

        # Get the key which was used to encrypt the session key
        key = message.keys.get(key_id)
        if not key:
            raise errors.PGPException("Data was encrypted with RSA key '%d', which was't found" % key_id)

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
        encrypted_session_key = encrypted_session_key.rjust(key_size, '\0')

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

class SignatureParser(Parser):
    """Signature packets describes a binding between some public key and some data"""
    def consume(self, tag, message, region):
        version = region.read(8).uint
        self.only_implemented(version, (4, ), "version four signature packets")

        signature_type = region.read(8).uint
        self.only_implemented(signature_type, (0x13, 0x18), "UserId and Subkey binding signatures")

        public_key_algorithm = region.read(8).uint
        self.only_implemented(public_key_algorithm, (1, ), "RSA Encrypt or sign public keys")

        hash_algorithm = region.read(8).uint
        self.only_implemented(hash_algorithm, (2, ), "SHA-1 hashing")

        # Determine hashed data
        hashed_subpacket_length = region.read(8*2).uint
        hashed_subpacket_data = message.consume_subsignature(region.read(hashed_subpacket_length * 8))

        # Not cyrptographically protected by signature
        # Should only contain advisory information
        unhashed_subpacket_length = region.read(8*2).uint
        unhashed_subpacket_data = message.consume_subsignature(region.read(unhashed_subpacket_length * 8))

        # Left 16 bits of the signed hash value provided for a heuristic test for valid signatures
        left_of_signed_hash = region.read(8*2)

        # Get the mpi value for the RSA hash
        # RSA signature value m**d mod n
        mdn = self.parse_mpi(region).uint

        return None

class KeyParser(Parser):
    def consume(self, tag, message, region):
        info = self.consume_common(tag, message, region)
        info['mpi_values'] = self.consume_mpi(tag, message, region, algorithm=info['algorithm'])
        self.consume_rest(tag, message, region, info)
        self.add_value(message, info)
    
    def consume_rest(self, tag, message, region, info):
        """Have common things to all keys in info"""
        pass
    
    def add_value(self, message, info):
        """Used to add information for this key to the message"""
        raise NotImplementedError
    
    def consume_common(self, tag, message, region):
        """Common to all key types"""
        key_version = region.read(8).uint
        self.only_implemented(key_version, (4, ), "version 4 keys. Upgrade your PGP!")

        # The creation time of the key
        # And key algorithm used by this key
        ctime = region.read(8*4).uint
        algorithm = region.read(8).uint
        
        return dict(tag=tag, key_version=key_version, ctime=ctime, algorithm=algorithm)
    
    def consume_mpi(self, tag, message, region, algorithm):
        """Return dict of mpi values for the specified algorithm"""
        if algorithm in (1, 2, 3):
            return self.rsa_mpis(region)
        
        elif algorithm in (16, 20):
            return self.elgamal_mpis(region)
        
        elif algorithm == 17:
            return self.dsa_mpis(region)
        
        else:
            raise errors.PGPException("Unknown public key type %d" % algorithm)
    
    def rsa_mpis(self, region):
        """n and e"""
        n = self.parse_mpi(region)
        e = self.parse_mpi(region)
        return dict(n=n, e=e)
    
    def elgamal_mpis(self, region):
        """p, g and y"""
        p = self.parse_mpi(region)
        g = self.parse_mpi(region)
        y = self.parse_mpi(region)
        return dict(p=p, g=g, y=y)
    
    def dsa_mpis(self, region):
        """p, q, g and y"""
        p = self.parse_mpi(region)
        q = self.parse_mpi(region)
        g = self.parse_mpi(region)
        y = self.parse_mpi(region)
        return dict(p=p, q=q, g=g, y=y)

class PublicKeyParser(KeyParser):
    def add_value(self, message, info):
        message.add_public_key(info)

class SecretKeyParser(KeyParser):
    def add_value(self, message, info):
        message.add_secret_key(info)
    
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
        pass

class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_public_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_secret_key(info)

class CompressedParser(Parser):
    """Parse compressed packets"""
    def consume(self, tag, message, region):
        # Get the compression algorithm used
        algo = region.read(8).uint
        self.only_implemented(algo, (1, ), "ZIP compression")

        # Use zlib to decompress the packet. The -15 at the end is the window size.
        # It says to ignore the zlib header (because it's negative) and that the
        # data is compressed with up to 15 bits of compression.
        uncompressed = zlib.decompress(region.read('bytes'), -15)

        # Parse the inner packet and return it
        return message.consume(uncompressed)

class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    # Mapping of PGP encryption algorithm types to a PyCrypto module which implements
    # that particular algorithm
    ENCRYPTION_ALGORITHMS = {
        3: CAST,  # CAST5
    }

    def consume(self, tag, message, region, algo, session_key):
        # Get the encryption algorithm used
        cipher = self.ENCRYPTION_ALGORITHMS.get(algo)
        if not cipher:
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
        return message.consume(decrypted)

class LiteralParser(Parser):
    """Extracts various information from the packet but only returns the plaintext"""
    def consume(self, tag, message, region):
        # Is it binary ('b'), text ('t') or utf-8 text ('u')
        format = region.read(8).bytes

        # The length of the filename in bytes
        filename_length = region.read(8).uint

        # Read in the filename
        if filename_length:
            filename = region.read(filename_length*8).bytes

        # Read in the date (can mean anything. ie. creation, modification, or 0)
        date = region.read(8*4).uint

        # Add the literal data to the list of decrypted plaintext
        message.add_plaintext(region.read('bytes'))

class UserIdParser(Parser):
    """Parses type-13 packets, which contain information about the user"""
    def consume(self, tag, message, region):
        message.userid = region.read('bytes')
