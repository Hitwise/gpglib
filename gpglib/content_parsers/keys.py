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
        # Get values
        version, signature_type, public_key_algorithm, hash_algorithm, hashed_subpacket_length = region.readlist("""
        uint:8,  uint:8,         uint:8,               uint:8,         uint:16""")
        
        # Complain if any values haven't been implemented yet
        self.only_implemented(version, (4, ), "version four signature packets")
        self.only_implemented(signature_type, (0x13, 0x18), "UserId and Subkey binding signatures")
        self.only_implemented(public_key_algorithm, (1, ), "RSA Encrypt or sign public keys")
        self.only_implemented(hash_algorithm, (2, ), "SHA-1 hashing")

        # Determine hashed data
        hashed_subpacket_data = message.consume_subsignature(region.read(hashed_subpacket_length * 8))

        # Not cyrptographically protected by signature
        # Should only contain advisory information
        unhashed_subpacket_length = region.read('uint:16')
        unhashed_subpacket_data = message.consume_subsignature(region.read(unhashed_subpacket_length * 8))

        # Left 16 bits of the signed hash value provided for a heuristic test for valid signatures
        left_of_signed_hash = region.read(8*2)

        # Get the mpi value for the RSA hash
        # RSA signature value m**d mod n
        mdn = self.parse_mpi(region).read('uint')

        return None

class KeyParser(Parser):
    def consume(self, tag, message, region):
        info = self.consume_common(tag, message, region)
        pos_before = region.pos
        info['mpi_values'] = self.consume_mpi(tag, message, region, algorithm=info['algorithm'])
        pos_after = region.pos
        region.pos = pos_before
        mpi_length = (pos_after - pos_before) / 8
        info['raw_mpi_values'] = region.read('bytes:%d' % mpi_length)
        self.consume_rest(tag, message, region, info)
        self.add_value(message, info)
    
    def consume_rest(self, tag, message, region, info):
        """Have common things to all keys in info"""
        pass
    
    def add_value(self, message, info):
        """Used to add information for this key to the message"""
        raise NotImplementedError
    
    def determine_key_id(self, info):
        # Calculate the key ID
        fingerprint_data = chr(info['key_version']) + \
                           bitstring.Bits(uint=info['ctime'], length=4*8).bytes + \
                           chr(info['algorithm']) + \
                           info['raw_mpi_values']
        fingerprint_length = len(fingerprint_data)
        fingerprint_data = '\x99' + \
                           chr((0xffff & fingerprint_length) >> 8) + \
                           chr(0xff & fingerprint_length) + \
                           fingerprint_data
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
        message.add_key(info)

    def consume_rest(self, tag, message, region, info):
        mpi_tuple = (info['mpi_values']['n'], info['mpi_values']['e'])
        info['key'] = RSA.construct(long(i.read('uint')) for i in mpi_tuple)
        info['key_id'] = self.determine_key_id(info)

class SecretKeyParser(PublicKeyParser):
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
        # Now for the secret portion of the key
        # Get the 'string-to-key' type of the secret key. If it's 0, the key is
        # not encrypted. If it's 254 or 255, it's the value of the string-to-key
        # specifier. If it's anything else, it's the type of symmetric encryption
        # algorithm used.
        s2k_type = region.read('uint:8')

        if s2k_type == 0:
            mpis = region

        elif s2k_type == 254:
            # Get the symmetric encryption algorithm used
            encryption_algo = region.read(8).uint

            # Get a cipher object we can use to decrypt the key (and fail if we can't)
            cipher = ENCRYPTION_ALGORITHMS.get(encryption_algo)
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
            # Read in the MPIs
            mpis = decrypted.read(decrypted.len-(8*20))

            # Hash the bytes
            generated_hash = SHA.new(mpis.bytes).digest()
            # Read in the 'real' hash
            real_hash = decrypted.read(160).bytes

            if generated_hash != real_hash:
                raise errors.PGPException("Secret key hashes don't match. Check your passphrase")
        else:
            raise NotImplementedError("String-to-key type '%d' not supported" % s2k_type)
        
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
        info['key'] = RSA.construct(long(i.read('uint')) for i in mpi_tuple)
        info['key_id'] = self.determine_key_id(info)
    
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
    
class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_key(info)
