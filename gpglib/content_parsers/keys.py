from gpglib import errors
from base import Parser

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
    def add_value(self, message, info):
        message.add_secret_key(info)
    
    def consume_rest(self, tag, message, region, info):
        """Already have public key things"""
        pass

class PublicSubKeyParser(PublicKeyParser):
    """Same format as Public Key"""
    def add_value(self, message, info):
        message.add_sub_public_key(info)

class SecretSubKeyParser(SecretKeyParser):
    """Same format as Secret Key"""
    def add_value(self, message, info):
        message.add_sub_secret_key(info)
