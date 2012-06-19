import itertools
import zlib

import bitstring
from Crypto import Random
from Crypto.Cipher import CAST, PKCS1_v1_5
from Crypto.Hash import SHA

import errors

# Mapping of PGP encryption algorithm types to a PyCrypto module which implements
# that particular algorithm
ENCRYPTION_ALGORITHMS = {
    3: CAST,  # CAST5
}

# Mapping of encryption algorithms to a their standard PGP key sizes
CIPHER_KEY_SIZES = {
    CAST: 16,  # CAST5
}

# Mapping of PGP hash algorithm types to a PyCrypto module which implements
# that particular algorithm
HASH_ALGORITHMS = {
    2: SHA,  # SHA-1
}

class ContentParser(object):
    """Delegator to the different content parsers"""
    def __init__(self):
        self.parsers = {}
        self.parse_unknown = Parser()
        
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
    
    def find_parsers(self):
        """
            Add parsers to this instance of ContentParser
            It's recommended that only one instance of this class is ever generated
            So this setup only has to happen once
        """
        parsers = (
              (1, PubSessionKeyParser)
            , (2, SecretKeyParser)
            , (5, SecretKeyParser)
            , (7, SecretKeyParser)
            , (8, CompressedParser)
            , (9, SymEncryptedParser)
            , (11, LiteralParser)
            , (13, UserIdParser)
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

    def parse_s2k(self, region, cipher=None, passphrase=None):
        # Get the 'string-to-key specifier'
        s2k_specifier = region.read(8).uint

        if s2k_specifier != 3:  # we only support '3' (iterated + salted) for now
            raise NotImplementedError("String-to-key type '%d' hasn't been implemented" % s2k_specifier)

        # The hash algorithm used by the string-to-key value
        s2k_hash_algo = region.read(8).uint

        # Get a hash object we can use
        hasher = HASH_ALGORITHMS.get(s2k_hash_algo)
        if not hasher:
            raise NotImplementedError("Hash type '%d' hasn't been implemented" % s2k_hash_algo)

        # The salt value used for the hash
        salt = region.read(8*8).bytes

        # The 'count' is the length of the data that gets hashed
        raw_count = region.read(8).uint
        count = (16 + (raw_count & 15)) << ((raw_count >> 4) + 6)

        # The size of the key (in bytes)
        key_size = CIPHER_KEY_SIZES[cipher]

        # TODO: Clean this up

        # Initialize the result to an empty string
        result = ''

        # Infinite for loop
        for i in itertools.count():
            # Initialize an infinite stream of salts + passphrases
            stream = itertools.cycle(list(salt + passphrase))

            # Initialize the message, which is at a minimum:
            #   some nulls || salt || passphrase
            message = ('\x00' * i) + salt + passphrase

            # Fill the rest of the message (up to `count`) with the string `salt + passphrase`
            message += ''.join(itertools.islice(stream, count - len(message)))

            # Now hash the message
            hash = hasher.new(message).digest()

            # Append the message to the result, until len(result) == count
            size = min(len(hash), key_size - len(result))
            result += hash[0:size]

            # Break if the result is large enough
            if len(result) >= key_size:
                break

        return result

class PubSessionKeyParser(Parser):
    """Parse public session key packet"""
    def consume(self, tag, message, region):
        # Version of the packet we're parsing (almost always '3')
        version = region.read(8).uint

        # The id of the key used to encrypt the session key
        key_id = region.read(8*8).uint

        # The public key algorithm used to encrypt the session key
        key_algo = region.read(8).uint

        if key_algo != 1:
            # not RSA-encrypted session key
            # TODO: Implement Elgamal
            raise NotImplementedError("Session keys encrypted with public key type '%d' not implemented" % key_algo)

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

class SecretKeyParser(Parser):
    def consume(self, tag, message, region):
        if tag.tag_type == 2 or tag.tag_type == 5:
            return
        # TODO: Refactor out the public-key portion of this function when we need
        # to parse public key packets

        # Get the version of the public key
        public_key_version = region.read(8).uint

        # Only version 4 packets are supported
        if public_key_version != 4:
            raise NotImplementedError("Public key versions != 4 are not supported. Upgrade your PGP!")

        # The creation time of the secret key
        ctime = region.read(8*4).uint

        # Get the public key algorithm used by this key
        public_key_algo = region.read(8).uint

        if public_key_algo != 1:  # only RSA is supported
            raise NotImplementedError("Public key algorithm '%d' not supported" % public_key_algo)

        # Get the `n` value of the RSA public key (encoded as an MPI)
        rsa_n = self.parse_mpi(region).uint

        # Get the exponent of the RSA public key (encoded as an MPI)
        rsa_e = self.parse_mpi(region).uint

        # Now for the secret portion of the key
        # Get the 'string-to-key' type of the secret key. If it's 0, the key is
        # not encrypted. If it's 254 or 255, it's the value of the string-to-key
        # specifier. If it's anything else, it's the type of symmetric encryption
        # algorithm used.
        s2k_type = region.read(8).uint

        if s2k_type != 254:  # for now, force s2k == 254
            raise NotImplementedError("String-to-key type '%d' not supported" % s2k_type)
        
        # Get the symmetric encryption algorithm used
        encryption_algo = region.read(8).uint

        # Get a cipher object we can use to decrypt the key (and fail if we can't)
        cipher = ENCRYPTION_ALGORITHMS.get(encryption_algo)
        if not cipher:
            raise NotImplementedError("Symmetric encryption type '%d' hasn't been implemented" % algo)

        # This is the passphrase used to decrypt the secret key
        key_password = self.parse_s2k(region, cipher, 'Hitwise')

        # The IV is the next `block_size` bytes
        iv = region.read(cipher.block_size*8).bytes

        # Initialize our decryptor
        decryptor = cipher.new(key_password, cipher.MODE_OPENPGP, iv)

        # Fetch and decrypt the ciphertext (the remaining bytes in `region`)

        encrypted = region.read('bytes')
        #decrypted = decryptor.decrypt(encrypted)
        decrypted = decryptor.decrypt(encrypted)

        crap2 = '\x0f\xf8\xf6K\x15\xda\x99\xf8'
        crap = ''
        for i, thing in enumerate(iv):
            crap += chr(ord(thing) ^ ord(encrypted[i]))
            print bin(ord(encrypted[i])), bin(ord(thing)), bin(ord(crap2[i]))
        decrypted = crap + decrypted[8:]
        print decrypted.encode('string_escape')
        stream = bitstring.ConstBitStream(bytes=decrypted)

        hash = SHA.new(stream.read(stream.len-160).bytes).digest()
        print hash.encode('string_escape'), stream.read(160).bytes.encode('string_escape')


class CompressedParser(Parser):
    """Parse compressed packets"""
    def consume(self, tag, message, region):
        # Get the compression algorithm used
        algo = region.read(8).uint

        if algo != 1:  # we only support ZIP compression for now
            raise NotImplementedError("Compression type '%d' not supported" % algo)

        # Use zlib to decompress the packet. The -15 at the end is the window size.
        # It says to ignore the zlib header (because it's negative) and that the
        # data is compressed with up to 15 bits of compression.
        uncompressed = zlib.decompress(region.read('bytes'), -15)

        # Parse the inner packet and return it
        return message.consume(uncompressed)

class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    def consume(self, tag, message, region, algo, session_key):
        # Get the encryption algorithm used
        cipher = ENCRYPTION_ALGORITHMS.get(algo)
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
        message.userid = region.bytes
