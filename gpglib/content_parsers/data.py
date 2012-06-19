from base import Parser

from Crypto.Cipher import CAST
import zlib

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
