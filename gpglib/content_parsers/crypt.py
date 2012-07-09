from gpglib import errors

from Crypto.PublicKey import RSA, DSA, ElGamal
from Crypto.Hash import SHA, SHA256
from Crypto.Cipher import CAST, AES, Blowfish
from Crypto import Random

import bitstring
import zlib
import bz2

####################
### MAPPINGS
####################

class Mapping(object):
    """
        Thin class that gives item access to some map of values
        That raises a NotImplementedError if you try to access something not defined on it
    """
    def __init__(self, typ, map):
        self.map = map
        self.type = typ

    def __getitem__(self, key):
        """Complain if key isn't known"""
        if key not in self.map:
            raise NotImplementedError("Haven't implemented %s : %s" % (self.type, key))
        return self.map[key]

class Algorithms(object):
    encryption = Mapping("Symmetric encryption algorithm",
        { 3 : CAST     # CAST5 128-bit key
        , 4 : Blowfish # Blowfish 128-bit key
        , 7 : AES      # AES 128-bit key
        }
    )

    hashes = Mapping("Hash Algorithm",
        { 2 : SHA    # SHA-1
        , 8 : SHA256 # SHA-256
        }
    )

    keys = Mapping("Key algorithm",
        { 1  : RSA     # Encrypt or Sign
        , 2  : RSA     # Encrypt Only
        , 3  : RSA     # Sign Only
        , 16 : ElGamal # Encrypt Only
        , 17 : DSA     # Digital Signature Algorithm
        }
    )

class Ciphers(object):
    key_sizes = Mapping("Cipher key size",
        { CAST : 16 # CAST5
        }
    )

class Compression(object):
    def decompress_zip(compressed):
        """
            To decompress zip, we use zlib with a -15 window size.
            It says to ignore the zlib header
            and that the data is compressed with up to 15 bits of compression.
        """
        return zlib.decompress(compressed, -15)
    
    decompression = Mapping("Decompressor",
        { 1 : decompress_zip  # ZIP
        , 2 : zlib.decompress # ZLIB
        , 3 : bz2.decompress  # BZIP2
        }
    )

class Mapped(object):
    ciphers = Ciphers
    algorithms = Algorithms
    compression = Compression
    
####################
### PKCS
####################

class PKCS(object):
    @classmethod
    def consume(cls, region, key_algorithm, key):
        # Get the mpi values from the region according to key_algorithm
        # And decrypt them with the provided key
        mpis = tuple(mpi.bytes for mpi in Mpi.consume_encryption(region, key_algorithm))
        padded = bitstring.ConstBitStream(bytes=key.decrypt(mpis))

        # Default decrypted to random values
        # And only set to the actual decrypted value if all conditions are good
        decrypted = Random.new().read(19)

        # First byte needs to be 02
        if padded.read("bytes:1") == '\x02':
            # Find the next 00
            pos_before = padded.bytepos
            padded.find('0x00', bytealigned=True)
            pos_after = padded.bytepos

            # The ps section needs to be greater than 8
            if pos_after - pos_before >= 8:
                # Read in the seperator 0 byte
                sep = padded.read("bytes:1")

                # Decrypted value is the rest of the padded value
                decrypted = padded.read("bytes")

        # Read in and discard the rest of padded if not already read in
        padded.read("bytes")

        # Make a bitstream to read from
        return bitstring.ConstBitStream(bytes=decrypted)

####################
### MPI VALUES
####################

class Mpi(object):
    """Object to hold logic for getting multi precision integers from a region"""
    @classmethod
    def parse(cls, region):
        """Retrieve one MPI value from the region"""
        # Get the length of the MPI to read in
        raw_mpi_length = region.read('uint:16')
        
        # Read in the MPI bytes and return the resulting bitstream
        mpi_length = (raw_mpi_length + 7) / 8
        return region.read(mpi_length*8)

    @classmethod
    def retrieve(cls, region, mpis):
        """
            Helper to get multiple mpis from a region
            Allows some nice declarativity below....
        """
        return tuple(cls.parse(region) for mpi in mpis)
    
    ####################
    ### RFC4880 5.1
    ####################

    @classmethod
    def consume_encryption(cls, region, algorithm):
        """Retrieve necessary MPI values from a public session key"""
        if algorithm is RSA:
            return cls.retrieve(region, ('m**e mod n', ))
        
        elif algorithm is ElGamal:
            return cls.retrieve(region, ('g**k mod p', 'm * y**k mod p'))
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for encryption %d" % algorithm)
    
    ####################
    ### RFC4880 5.5.2 and 5.5.3
    ####################

    @classmethod
    def consume_public(cls, region, algorithm):
        """Retrieve necessary MPI values from a public key for specified algorithm"""
        if algorithm is RSA:
            return cls.retrieve(region, ('n', 'e'))
        
        elif algorithm is ElGamal:
            return cls.retrieve(region, ('p', 'g', 'y'))
        
        elif algorithm is DSA:
            return cls.retrieve(region, ('p', 'q', 'g', 'y'))
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for public keys %d" % algorithm)

    @classmethod
    def consume_private(cls, region, algorithm):
        """Retrieve necessary MPI values from a secret key for specified algorithm"""
        if algorithm is RSA:
            return cls.retrieve(region, ('d', 'p', 'q', 'r'))
        
        elif algorithm is ElGamal:
            return cls.retrieve(region, ('x', ))
        
        elif algorithm is DSA:
            return cls.retrieve(region, ('x', ))
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for secret keys %d" % algorithm)
