from gpglib import errors

from Crypto.PublicKey import RSA, DSA, ElGamal
from Crypto.Hash import SHA, SHA256
from Crypto.Cipher import CAST
import zlib

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
        { 3 : CAST # CAST5
        }
    )

    hashes = Mapping("Hash Algorithm",
        { 2 : SHA # SHA-1
        , 8 : SHA256 # SHA-256
        }
    )

    keys = Mapping("Key algorithm",
        { 1 : RSA # Encrypt or sign
        , 2 : RSA # Encrypt only
        , 3 : RSA # sign only
        , 16 : ElGamal # Encrypt only
        , 17 : DSA # Digital Signature Algorithm
        }
    )

class Ciphers(object):
    key_sizes = Mapping("Cipher key size",
        { CAST : 16 # CAST5
        }
    )

class Compression(object):
    def decompress_zlib(compressed):
        # The -15 at the end is the window size.
        # It says to ignore the zlib header (because it's negative) and that the
        # data is compressed with up to 15 bits of compression.
        return zlib.decompress(compressed, -15)
    
    decompression = Mapping("Decompressor",
        { 1 : decompress_zlib
        }
    )

class Mapped(object):
    ciphers = Ciphers
    algorithms = Algorithms
    compression = Compression

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
    
    ####################
    ### RFC4880 5.1
    ####################

    @classmethod
    def consume_encryption(cls, region, algorithm):
        """Retrieve necessary MPI values from a public session key"""
        if algorithm is RSA:
            # multiprecision integer (MPI) of RSA encrypted value m**e mod n.
            return (cls.parse(region), )
        
        elif algorithm is ElGamal:
            # MPI of Elgamal (Diffie-Hellman) value g**k mod p.
            # MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
            return (cls.parse(region), cls.parse(region))
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for encryption %d" % algorithm)
    
    ####################
    ### RFC4880 5.5.2 and 5.5.3
    ####################

    @classmethod
    def consume_public(cls, region, algorithm):
        """Retrieve necessary MPI values from a public key for specified algorithm"""
        if algorithm is RSA:
            return cls.rsa_mpis_public(region)
        
        elif algorithm is ElGamal:
            return cls.elgamal_mpis_public(region)
        
        elif algorithm is DSA:
            return cls.dsa_mpis_public(region)
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for public keys %d" % algorithm)

    @classmethod
    def consume_private(cls, region, algorithm):
        """Retrieve necessary MPI values from a private key for specified algorithm"""
        if algorithm is RSA:
            return cls.rsa_mpis_private(region)
        
        elif algorithm is ElGamal:
            return cls.elgamal_mpis_private(region)
        
        elif algorithm is DSA:
            return cls.dsa_mpis_private(region)
        
        else:
            raise errors.PGPException("Unknown mpi algorithm for secret keys %d" % algorithm)

    ####################
    ### RSA
    ####################

    @classmethod
    def rsa_mpis_public(cls, region):
        """n and e"""
        n = cls.parse(region)
        e = cls.parse(region)
        return (n, e)

    @classmethod
    def rsa_mpis_private(cls, region):
        """d, p, q and r"""
        d = cls.parse(region)
        p = cls.parse(region)
        q = cls.parse(region)
        r = cls.parse(region)
        return (d, p, q, r)
    
    ####################
    ### ELGAMAL
    ####################
    
    @classmethod
    def elgamal_mpis_public(cls, region):
        """p, g and y"""
        p = cls.parse(region)
        g = cls.parse(region)
        y = cls.parse(region)
        return (p, g, y)
    
    @classmethod
    def elgamal_mpis_private(cls, region):
        """x"""
        x = cls.parse(region)
        return (x, )
    
    ####################
    ### DSA
    ####################
    
    @classmethod
    def dsa_mpis_public(cls, region):
        """p, q, g and y"""
        p = cls.parse(region)
        q = cls.parse(region)
        g = cls.parse(region)
        y = cls.parse(region)
        return (p, q, g, y)
    
    @classmethod
    def dsa_mpis_private(cls, region):
        """x"""
        x = cls.parse(region)
        return (x, )
