from gpglib.structures import Key

from Crypto.PublicKey import RSA
import os

this_folder = os.path.dirname(__file__)
data_folder = os.path.join(this_folder, '..', 'data')

def get_file(name):
    file_path = os.path.join(data_folder, name)
    with open(file_path, 'r') as f:
        return f.read()

def get_original(namespace):
    return get_file("data.%s.dump" % namespace)

def get_encrypted(namespace, algo):
    return get_file("data.%s.dump.%s.gpg" % (namespace, algo))

def get_pgp_key(namespace, algo):
    return get_file("key.%s.%s.gpg" % (namespace, algo))
    
def get_keys(algo):
    key = Key(passphrase='blahandstuff').parse(get_pgp_key('secret', algo))
    return key.key_dict()
