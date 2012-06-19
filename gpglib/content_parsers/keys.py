from gpglib import utils, errors
from base import Parser

from Crypto.Cipher import CAST
from cStringIO import StringIO
from Crypto.Hash import SHA
import bitstring
import binascii
import hashlib

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
        key_version = region.read(8).uint
        self.only_implemented(key_version, (4, ), "version 4 keys. Upgrade your PGP!")

        # The creation time of the key
        # And key algorithm used by this key
        ctime = region.read(8*4).uint
        algorithm = region.read(8).uint
        
        return dict(tag=tag, key_version=key_version, ctime=ctime, algorithm=algorithm)
    
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
    ENCRYPTION_ALGORITHMS = {
        3: CAST,  # CAST5
    }
    
    def add_value(self, message, info):
        message.add_secret_key(info)
    
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
        s2k_usage = region.read(8).uint
        self.only_implemented(s2k_usage, (254, ), "Encrypted and hashed string to key (254)")
        
        symmetric_algorithm = region.read(8).uint
        self.only_implemented(symmetric_algorithm, (3, ), "Symmetric algorithm 3")
        
        s2k_specifier = region.read(8).uint
        self.only_implemented(s2k_specifier, (3, ), "Salted and iterated s2k (3)")
        
        hash_algorithm = region.read(8).uint
        self.only_implemented(hash_algorithm, (2, ), "SHA1 Hash algorithm")
        
        salt = region.read(8*8).bytes
        coded_count = region.read(8).uint
        octet_count = (16 + (coded_count & 15)) << ((coded_count >> 4) + 6)
        
        # Decrypt the rest of the message
        # Openssl/cast.h says CAST_KEY_LENGTH is 16
        # But PyCrypto CAST.key_size is xrange(5, 17)
        keysize = 16
        
        # Hash size is 20 for sha1
        hashsize = 20
        hasher = hashlib.sha1
        key = self.get_key(keysize, octet_count, hashsize, hasher, message.passphrase, salt)
        
        iv = region.read(CAST.block_size * 8).bytes
        #cipher = CAST.new(key, CAST.MODE_OPENPGP, iv)
        #result = cipher.decrypt(region.read('bytes'))
        result = self.crypt_CFB(region, CAST, key, iv)
        decrypted = bitstring.ConstBitStream(bytes=result)
        
        hash = SHA.new()
        hash.update(result)
        sha_hash = hash.hexdigest()
        
        # Get mpi values from decrypted
        rsa_d = self.parse_mpi(decrypted)
        rsa_p = self.parse_mpi(decrypted)
        rsa_q = self.parse_mpi(decrypted)
        rsa_u = self.parse_mpi(decrypted)
    
    def crypt_CFB(self, region, ciphermod, key, iv):
        """
            Shamelessly stolen from OpenPGP
            http://pypi.python.org/pypi/OpenPGP
        """
        cipher = ciphermod.new(key, ciphermod.MODE_ECB)
        encrypt = cipher.encrypt
        shift = ciphermod.block_size * 8# number of bytes to process (normally 8)
        
        def str2int(s):
            l = 0L

            for i in map(ord, s):
                l = (l * 256) + i

            try:
                return int(l)

            except OverflowError:
                return l
        
        def int2str(n):
            h = hex(n)[2:] # chop off the '0x' 
            if h[-1] in ['l', 'L']:
                h = h[:-1]
            if 1 == len(h) % 2: # odd string, add '0' to beginning
                h = ''.join(['0', h])
            return binascii.unhexlify(h)
        
        apply_mask = lambda c,m: int2str(str2int(c) ^ str2int(m))
        
        blocks = []
        while True:
            chunk = StringIO()
            
            if shift > (region.len - region.pos):
                shift = region.len - region.pos
            
            if region.pos != region.len:
                inblock = region.read(shift).bytes
                mask = encrypt(iv)
                chunk.seek(0)
                
                for i, c in enumerate(inblock):
                    m = mask[i]
                    chunk.write(apply_mask(c, m))

                chunk.truncate()
                chunk.seek(0)
                outblock = chunk.read()
                iv = inblock
                blocks.append(outblock)

            else:
                break
        
        return ''.join(blocks)
    
    def get_key(self, keysize, octet_count, hashsize, hasher, passphrase, salt):
        """
            Not sure how it works but I think it does....
            Many thanks to OpenPGP where I shamelessly took this from
            http://pypi.python.org/pypi/OpenPGP
        """
        pos, run, result = 0, 0, ''
        count = octet_count
        len_passphrase = len(passphrase)
        while pos < keysize:
            md = [] # reset message digest "hash context" every run
            done = 0
            for i in range(run): # preloaded 0x00s depending on iteration "run"
                md.append('\x00')
            if count < (len_passphrase + len(salt)):
                count = len_passphrase + len(salt)
            while (count - done) > (len_passphrase + len(salt)):
                if (len(salt) > 0):
                    md.append(salt)
                md.append(passphrase)
                done = done + len_passphrase + len(salt)
            for i in range(len(salt)):
                if done < count:
                    md.append(salt[i])
                    done += 1
            for i in range(len_passphrase):
                if done < count:
                    md.append(passphrase[i]) 
                    done += 1
            hash = hasher(''.join(md)).digest()
            size = len(hash)
            if (pos + size) > keysize:
                size = keysize - pos
            result = ''.join([result[:pos], hash[0:size]])
            pos += size
            run += 1
        
        return result

class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_public_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_secret_key(info)
