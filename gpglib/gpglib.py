import zlib
from collections import namedtuple

import bitstring
from Crypto.PublicKey import RSA
from Crypto.Cipher import CAST

# Information obtained from an OpenPGP header
Tag = namedtuple('Tag', ('version', 'type', 'length'))

class PGPException(Exception):
    pass

class PGPFormatException(PGPException):
    pass

class OpenPGPDecryptor(object):
    def __init__(self, keys):
        self.keys = keys

        # Lots of definitions which need to be here, since they reference
        # functions defined in this class:

        # Mapping of OpenPGP packet types to functions which parse them
        self.PACKET_TYPE_PARSERS = {
            1: self._parse_pubkey_session_key,  # Public-Key Encrypted Session Key Packet
        }

    def decrypt(self, packet):
        self.bytes = bitstring.ConstBitStream(bytes=packet)
        return self._parse_tag()

    def _parse_session_key(self, session_key):
        # Convert the session key into a MPI (look at the RFC)
        session_key_mpi = bitstring.ConstBitStream(bytes=session_key).uint

        print session_key_mpi

    def _parse_mpi(self, bytes=None):
        if not bytes:
            bytes = self.bytes

        # Get the length of the MPI to read in
        raw_mpi_length = bytes.read(2*8).uint
        mpi_length = (raw_mpi_length + 7) / 8

        # Read in the MPI bytes and return the resulting integer
        return bytes.read(mpi_length*8).uint
    
    def _parse_pubkey_session_key(self, tag):
        # Version of the packet we're parsing (almost always '3')
        version = self.bytes.read(8).uint

        # The id of the key used to encrypt the session key
        key_id = self.bytes.read(8*8).uint

        # The public key algorithm used to encrypt the session key
        key_algo = self.bytes.read(8).uint

        if key_algo != 1:  # not RSA-encrypted session key
            # TODO: Implement Elgamal
            raise NotImplementedError("Session keys encrypted with public key type '%d' not implemented" % key_algo)

        # Get the key which was used to encrypt the session key
        try:
            key = self.keys[key_id]
        except KeyError:
            raise PGPException("Data was encrypted with RSA key '%x', which was't found" % key_id)

        # Read the encrypted session key
        encrypted_session_key = self._parse_mpi()

        # Decrypt the session key
        session_key = key.decrypt(encrypted_session_key)

        # Parse the session key
        return self._parse_session_key(session_key)

    def _parse_tag(self):
        # Read in the first byte from the stream as the tag byte and convert it
        # into an int
        tag = self.bytes.read(8)

        # The left-most bit *MUST* be 1
        if not tag.read(1).uint:
            raise PGPFormatException("The left-most bit of the tag ('%x') was not 1" % tag)

        # The version is stored in the second bit from the left
        version = tag.read(1).uint

        if version != 0:
            # TODO: Implement the new length format when we find the need to
            raise NotImplementedError("The new PGP length format is not handled yet")

        # Old length type
        # Get the packet type (bits 3-6)
        type = tag.read(4).uint

        # Get the type of length
        length_type = tag.read(2).uint

        # If the length type is 3 (ie. no length), throw an error
        if length_type == 3:
            raise NotImplementedError("PGP messages with a null length are not yet supported")

        # Find the length of the message
        octet_length = 2**length_type
        length = self.bytes.read(octet_length*8).uint

        # Call the next parser
        tag = Tag(version=version, type=type, length=length)
        try:
            func = self.PACKET_TYPE_PARSERS[tag.type]
            return func(tag)
        except KeyError:
            raise NotImplementedError("No parser function found for type '%d'" % tag.type)
