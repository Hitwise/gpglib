from crypt import Mapped
from base import Parser

class CompressedParser(Parser):
    """Parse compressed packets"""
    def consume(self, tag, message, region):
        # Get the compression algorithm used
        # And the rest of the message
        algo, rest = region.readlist('uint:8, bytes')

        # Get decompressor and use it to decompress the packet
        decompressor = Mapped.compression.decompression[algo]
        uncompressed = decompressor(rest)

        # Parse the inner packet and return it
        return message.consume(uncompressed)

class SymEncryptedParser(Parser):
    """Parse symmetrically encrypted data packet"""
    def consume(self, tag, message, region, algo, session_key):
        # Get the encryption algorithm used
        cipher = Mapped.algorithms.encryption[algo]

        # Handy alias for the encryption algo's block size
        block_size = cipher.block_size

        # Find out the length of the IV
        iv_len = block_size + 2

        # Read in the encrypted IV
        # The ciphertext is what's left in `region` after the iv
        iv, ciphertext = region.readlist('bytes:%d, bytes' % iv_len)

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
        # The length of the filename in bytes
        format, filename_length = region.readlist('bytes:1, uint:8')

        # Read in filename
        # Read in the date (can mean anything. ie. creation, modification, or 0)
        filename, date = region.readlist('bytes:%d, uint:32' % filename_length)

        # Add the literal data to the list of decrypted plaintext
        message.add_plaintext(region.read('bytes'))

class UserIdParser(Parser):
    """Parses type-13 packets, which contain information about the user"""
    def consume(self, tag, message, region):
        message.userid = region.read('bytes')
