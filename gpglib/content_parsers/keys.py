from gpglib import utils, errors
from base import Parser, ENCRYPTION_ALGORITHMS, CIPHER_KEY_SIZES, HASH_ALGORITHMS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

import itertools
import bitstring
import binascii

class SignatureParser(Parser):
    """Signature packets describes a binding between some public key and some data"""
    def consume(self, tag, message, region):
        version = region.read(8).uint
        self.only_implemented(version, (4, ), "version four signature packets")

        signature_type = region.read(8).uint
        self.only_implemented(signature_type, (0x13, 0x18), "UserId and Subkey binding signatures")

        public_key_algorithm = region.read(8).uint
        self.only_implemented(public_key_algorithm, (1, ), "RSA Encrypt or sign public keys")

        hash_algorithm = region.read(8).uint
        self.only_implemented(hash_algorithm, (2, ), "SHA-1 hashing")

        # Determine hashed data
        hashed_subpacket_length = region.read(8*2).uint
        hashed_subpacket_data = message.consume_subsignature(region.read(hashed_subpacket_length * 8))

        # Not cyrptographically protected by signature
        # Should only contain advisory information
        unhashed_subpacket_length = region.read(8*2).uint
        unhashed_subpacket_data = message.consume_subsignature(region.read(unhashed_subpacket_length * 8))

        # Left 16 bits of the signed hash value provided for a heuristic test for valid signatures
        left_of_signed_hash = region.read(8*2)

        # Get the mpi value for the RSA hash
        # RSA signature value m**d mod n
        mdn = self.parse_mpi(region).uint

        return None

class KeyParser(Parser):
    def consume(self, tag, message, region):
        info = self.consume_common(tag, message, region)
        info['mpi_values'] = self.consume_mpi(tag, message, region, algorithm=info['algorithm'])
        self.consume_rest(tag, message, region, info)
        self.add_value(message, info)
    
    def consume_rest(self, tag, message, region, info):
        """Have common things to all keys in info"""
        pass
    
    def add_value(self, message, info):
        """Used to add information for this key to the message"""
        raise NotImplementedError
    
    def consume_common(self, tag, message, region):
        """Common to all key types"""
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
        
        return dict(tag=tag, key_version=public_key_version, ctime=ctime, algorithm=public_key_algo)
    
    def consume_mpi(self, tag, message, region, algorithm):
        """Return dict of mpi values for the specified algorithm"""
        if algorithm in (1, 2, 3):
            return self.rsa_mpis(region)
        
        elif algorithm in (16, 20):
            return self.elgamal_mpis(region)
        
        elif algorithm == 17:
            return self.dsa_mpis(region)
        
        else:
            raise errors.PGPException("Unknown public key type %d" % algorithm)
    
    def rsa_mpis(self, region):
        """n and e"""
        n = self.parse_mpi(region)
        e = self.parse_mpi(region)
        return dict(n=n, e=e)
    
    def elgamal_mpis(self, region):
        """p, g and y"""
        p = self.parse_mpi(region)
        g = self.parse_mpi(region)
        y = self.parse_mpi(region)
        return dict(p=p, g=g, y=y)
    
    def dsa_mpis(self, region):
        """p, q, g and y"""
        p = self.parse_mpi(region)
        q = self.parse_mpi(region)
        g = self.parse_mpi(region)
        y = self.parse_mpi(region)
        return dict(p=p, q=q, g=g, y=y)

class PublicKeyParser(KeyParser):
    def add_value(self, message, info):
        message.add_public_key(info)

class SecretKeyParser(KeyParser):
    def add_value(self, message, info):
        message.add_secret_key(info)
    
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
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
        key_passphrase = self.parse_s2k(region, cipher, 'blahandstuff')

        # The IV is the next `block_size` bytes
        iv = region.read(cipher.block_size*8).bytes

        # Use the hacky crypt_CFB func to decrypt the MPIs
        result = self.crypt_CFB(region, cipher, key_passphrase, iv)
        decrypted = bitstring.ConstBitStream(bytes=result)

        # The decrypted bytes are in the format of:
        #   MPIs || 20-octet SHA1 hash
        # Read in the MPIs
        mpis = decrypted.read(decrypted.len-(8*20))

        # Hash the bytes
        generated_hash = SHA.new(mpis.bytes).digest()
        # Read in the 'real' hash
        real_hash = decrypted.read(160).bytes

        if generated_hash != real_hash:
            raise errors.PGPException("Secret key hashes don't match. Check your passphrase")
        
        # Get mpi values from decrypted
        rsa_d = self.parse_mpi(mpis)
        rsa_p = self.parse_mpi(mpis)
        rsa_q = self.parse_mpi(mpis)
        rsa_u = self.parse_mpi(mpis)

        mpi_tuple = (
            info['mpi_values']['n'],
            info['mpi_values']['e'],
            rsa_d,
            rsa_p,
            rsa_q,
            rsa_u,
        )
        return RSA.construct(long(i.uint) for i in mpi_tuple)
    
    def crypt_CFB(self, region, ciphermod, key, iv):
        """
            Shamelessly stolen from OpenPGP (with some modifications)
            http://pypi.python.org/pypi/OpenPGP
        """
        cipher = ciphermod.new(key, ciphermod.MODE_ECB)
        shift = ciphermod.block_size * 8  # number of bytes to process (normally 8)
        
        blocks = []
        while region.pos != region.len:
            shift = min(shift, region.len-region.pos)
            
            inblock = region.read(shift).bytes
            mask = cipher.encrypt(iv)
            chunk = ''.join(chr(ord(c) ^ ord(m)) for m, c in itertools.izip(mask, inblock))
            iv = inblock
            blocks.append(chunk)

        return ''.join(blocks)
    
class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_public_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_secret_key(info)
