from gpglib import utils, errors
from crypt import Mapped, Mpi
from base import Parser

from Crypto.Hash import SHA

import itertools
import bitstring
import binascii

####################
### SIGNATURE
####################

class SignatureParser(Parser):
    """Signature packets describes a binding between some public key and some data"""
    def consume(self, tag, message, region):
        # Get values
        version, signature_type, public_key_algorithm, hash_algorithm, hashed_subpacket_length = region.readlist("""
        uint:8,  uint:8,         uint:8,               uint:8,         uint:16""")
        
        # Complain if any values haven't been implemented yet
        self.only_implemented(version, (4, ), "version four signature packets")
        self.only_implemented(signature_type, (0x13, 0x18), "UserId and Subkey binding signatures")

        # Get key algorithm
        algorithm = Mapped.algorithms.keys[public_key_algorithm]
        
        # Get hasher
        hasher = Mapped.algorithms.hashes[hash_algorithm]

        # Determine hashed data
        subsignature = region.read(hashed_subpacket_length * 8)
        hashed_subpacket_data = message.consume_subsignature(subsignature)

        # Not cyrptographically protected by signature
        # Should only contain advisory information
        unhashed_subpacket_length = region.read('uint:16')
        unhashed_subpacket_body = region.read(unhashed_subpacket_length * 8)
        unhashed_subpacket_data = message.consume_subsignature(unhashed_subpacket_body)

        # Left 16 bits of the signed hash value provided for a heuristic test for valid signatures
        left_of_signed_hash = region.read(8*2)

        # Get the mpi value for the RSA hash
        # RSA signature value m**d mod n
        mdn = Mpi.parse(region).read('uint')

####################
### BASE KEY PARSER
####################

class KeyParser(Parser):
    """
        Public and Secret keys are the same except Secret keys has some extra information
        SubKeys have the same format
        Hence the base takes care of all the common things to both formats and delegates the rest to the subclass
    """
    def consume(self, tag, message, region):
        info = self.consume_common(tag, message, region)

        # Get individual mpi_values and the raw bytes from the region for those values
        # The raw stream is required for the fingerprint data when determining key id
        mpi_values, raw_mpi_bytes = self.get_mpi_values(region, info['algorithm'])
        info['mpi_values'] = mpi_values
        info['raw_mpi_bytes'] = raw_mpi_bytes

        # Consume the rest of the Key
        self.consume_rest(tag, message, region, info)
        self.add_value(message, info)

    def get_mpi_values(self, region, algorithm):
        """
            * Determine position before
            * Get individual mpi values
            * Determine how much was read
            * Reset region to what it was before
            * Return byte stream for the amount read in the first pass
        """
        pos_before = region.pos
        mpi_values = Mpi.consume_public(region, algorithm)

        pos_after = region.pos
        region.pos = pos_before
        mpi_length = (pos_after - pos_before) / 8
        raw_mpi_bytes = region.read('bytes:%d' % mpi_length)

        return mpi_values, raw_mpi_bytes
    
    def consume_rest(self, tag, message, region, info):
        """Have common things to all keys in info"""
        pass
    
    def add_value(self, message, info):
        """Used to add information for this key to the message"""
        raise NotImplementedError
    
    def determine_key_id(self, info):
        """Calculate the key id"""
        fingerprint_data = ''.join(
            [ chr(info['key_version'])
            , bitstring.Bits(uint=info['ctime'], length=4*8).bytes
            , chr(info['algorithm'])
            , info['raw_mpi_bytes']
            ]
        )

        fingerprint_length = len(fingerprint_data)
        fingerprint_data = ''.join(
            [ '\x99'
            , chr((0xffff & fingerprint_length) >> 8)
            , chr(0xff & fingerprint_length)
            , fingerprint_data
            ]
        )

        fingerprint = SHA.new(fingerprint_data).hexdigest().upper()[-16:]
        return int(fingerprint, 16)
    
    def consume_common(self, tag, message, region):
        """Common to all key types"""
        # Version of the public key
        # Creation time of the secret key
        # Public key algorithm used by this key
        public_key_version, ctime,   public_key_algo = region.readlist("""
        uint:8,             uint:32, uint:8""")

        # Only version 4 packets are supported
        if public_key_version != 4:
            raise NotImplementedError("Public key versions != 4 are not supported. Upgrade your PGP!")

        # only RSA is supported
        self.only_implemented(public_key_algo, (1, 17, 16), "RSA and DSA keys")
        
        return dict(tag=tag, key_version=public_key_version, ctime=ctime, algorithm=public_key_algo)

####################
### PUBLIC KEY
####################

class PublicKeyParser(KeyParser):
    def add_value(self, message, info):
        message.add_key(info)

    def consume_rest(self, tag, message, region, info):
        algorithm = Mapped.algorithms.keys[info['algorithm']]
        info['key'] = algorithm.construct(list(long(i.read('uint')) for i in info['mpi_values']))
        info['key_id'] = self.determine_key_id(info)

####################
### SECRET KEY
####################

class SecretKeyParser(PublicKeyParser):
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
        s2k_type = region.read('uint:8')
        mpis = self.get_mpis(s2k_type, message, region, info)

        # Get the rest of the mpi values and combine with those from public portion
        mpi_values = Mpi.consume_private(mpis, info['algorithm'])
        mpi_tuple = info['mpi_values'] + mpi_values

        # Record key and key_id
        algorithm = Mapped.algorithms.keys[info['algorithm']]
        info['key'] = algorithm.construct(list(long(i.read('uint')) for i in mpi_tuple))
        info['key_id'] = self.determine_key_id(info)

    def get_mpis(self, s2k_type, message, region, info):
        """Get mpi values from region given specified string to key type"""
        self.only_implemented(s2k_type, (0, 254), "Unencrypted and s2k_type 254")

        # If string to key is:
        #   * 0 :: key is not encrypted.
        #   * 254 or 255 :: key is value of the string-to-key specifier
        #   * otherwise :: key is type of symmetric encryption algorithm used.
        if s2k_type == 0:
            # Unencrypted!
            mpis = region

        elif s2k_type == 254:
            # Get the symmetric encryption algorithm used
            encryption_algo = region.read(8).uint

            # Get a cipher object we can use to decrypt the key (and fail if we can't)
            cipher = Mapped.algorithms.encryption[encryption_algo]
            if not cipher:
                raise NotImplementedError("Symmetric encryption type '%d' hasn't been implemented" % algo)

            # This is the passphrase used to decrypt the secret key
            key_passphrase = self.parse_s2k(region, cipher, message.passphrase(message, info))

            # The IV is the next `block_size` bytes
            iv = region.read(cipher.block_size*8).bytes

            # Use the hacky crypt_CFB func to decrypt the MPIs
            result = self.crypt_CFB(region, cipher, key_passphrase, iv)
            decrypted = bitstring.ConstBitStream(bytes=result)

            # The decrypted bytes are in the format of:
            #   MPIs || 20-octet SHA1 hash
            # Read in the MPIs portion of this
            mpis = decrypted.read(decrypted.len-(8*20))

            # Hash the mpi bytes
            generated_hash = SHA.new(mpis.bytes).digest()

            # Read in the 'real' hash
            real_hash = decrypted.read("bytes:20")

            if generated_hash != real_hash:
                raise errors.PGPException("Secret key hashes don't match. Check your passphrase")

        return mpis
    
    def crypt_CFB(self, region, ciphermod, key, iv):
        """
            Shamelessly stolen from OpenPGP (with some modifications)
            http://pypi.python.org/pypi/OpenPGP
        """
        # Create the cipher
        cipher = ciphermod.new(key, ciphermod.MODE_ECB)
        
        # Determine how many bytes to process at a time
        shift = ciphermod.block_size
        
        # Create a bitstring list of ['bytes:8', 'bytes:8', 'bytes:3']
        # Such that the entire remaining region length gets consumed
        region_length = (region.len - region.pos) / 8
        region_datas = ['bytes:%d' % shift] * (region_length/shift)
        leftover = region_length % shift
        if leftover:
            region_datas.append('bytes:%d' % (region_length % shift))
        
        # Use the cipher to decrypt region
        blocks = []
        for inblock in region.readlist(region_datas):
            mask = cipher.encrypt(iv)
            chunk = ''.join(chr(ord(c) ^ ord(m)) for m, c in itertools.izip(mask, inblock))
            iv = inblock
            blocks.append(chunk)

        return ''.join(blocks)

####################
### SUB KEYS
####################
    
class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_key(info)
