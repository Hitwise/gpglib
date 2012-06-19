from gpglib import errors
from base import Parser

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
import bitstring

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
