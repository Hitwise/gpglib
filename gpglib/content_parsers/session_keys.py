from crypt import Mapped, PKCS
from gpglib import errors
from base import Parser

class PubSessionKeyParser(Parser):
    """Parse public session key packet"""
    def consume(self, tag, message, region):
        # Version of the packet we're parsing
        # The id of the key used to encrypt the session key
        # The public key algorithm used to encrypt the session key
        version, key_id, key_algo = region.readlist("""
        uint:8, uint:64, uint:8""")

        # Get key algorithm
        key_algorithm = Mapped.algorithms.keys[key_algo]

        # Get the key which was used to encrypt the session key
        key = message.keys.get(key_id)
        if not key:
            typ = key_algorithm.__name__
            typ = typ[typ.rfind('.')+1:]
            raise errors.PGPException("Data was encrypted with %s key '%d', which was't found" % (typ, key_id))
        
        # Use PKCS to consume the region and decrypt it
        # Also get back the size of the session key
        padded_session_key, key_size = PKCS.consume(region, key_algorithm, key)

        # The algorithm used to encrypt the message is the first byte
        # The session key is the next <key_size> bytes
        # The checksum is the last two bytes
        algo,   session_key, checksum = padded_session_key.readlist("""
        uint:8, bytes:%d,    uint:16""" % key_size)

        # Generate a checksum from the session_key (section 5.1 in the RFC).
        # This involves summing up all the bytes of the session key
        # and `mod`ing it by 65536.
        generated_checksum = sum(ord(i) for i in session_key) % 65536

        # Compare the checksums and throw an error if they don't match
        if checksum != generated_checksum:
            raise errors.PGPException("The decrypted session key was invalid (checksums didn't match)")

        # Pass the session key bytes and the algorithm used on to the next parser
        return dict(algo=algo, session_key=session_key)
