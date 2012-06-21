import itertools

from Crypto.Cipher import CAST
from Crypto.Hash import SHA

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
        raw_mpi_length = region.read('uint:16')
        
        # Read in the MPI bytes and return the resulting bitstream
        mpi_length = (raw_mpi_length + 7) / 8
        return region.read(mpi_length*8)

    def parse_s2k(self, region, cipher=None, passphrase=None):
        # string-to-key specifier'
        # Hash algorithm used by the string-to-key value
        # The salt value used for the hash
        # Count to determine how much data gets hashed
        s2k_specifier, s2k_hash_algo, salt,    raw_count = region.readlist("""
        uint:8,        uint:8,        bytes:8, uint:8""")

        if s2k_specifier != 3:  # we only support '3' (iterated + salted) for now
            raise NotImplementedError("String-to-key type '%d' hasn't been implemented" % s2k_specifier)

        # Get a hash object we can use
        hasher = HASH_ALGORITHMS.get(s2k_hash_algo)
        if not hasher:
            raise NotImplementedError("Hash type '%d' hasn't been implemented" % s2k_hash_algo)

        # The 'count' is the length of the data that gets hashed
        count = (16 + (raw_count & 15)) << ((raw_count >> 4) + 6)

        # The size of the key (in bytes)
        key_size = CIPHER_KEY_SIZES[cipher]
        
        # Initialize an infinite stream of salts + passphrases
        stream = itertools.cycle(list(salt + passphrase))
        
        # Infinite for loop
        result = []
        for i in itertools.count():
            # Initialize the message, which is at a minimum:
            #   some nulls || salt || passphrase
            message = ('\x00' * i) + salt + passphrase

            # Fill the rest of the message (up to `count`) with the string `salt + passphrase`
            message += ''.join(itertools.islice(stream, count - len(message)))

            # Now hash the message
            hash = hasher.new(message).digest()

            # Append the message to the result, until len(result) == count
            size = min(len(hash), key_size - len(result))
            result.extend(hash[0:size])

            # Break if the result is large enough
            if len(result) >= key_size:
                break

        return ''.join(result)
