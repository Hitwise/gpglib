from gpglib.structures import Key

from Crypto.PublicKey import RSA
import os

this_folder = os.path.dirname(__file__)
data_folder = os.path.join(this_folder, '..', 'data')

# Hold any cached values
cached = {}

def get_file(name):
    file_path = os.path.join(data_folder, name)
    with open(file_path, 'r') as f:
        return f.read()

def get_original(msg):
    return get_file("dump.%s" % msg)

def get_encrypted(msg, key, cipher, compression):
    fn = os.path.join("encrypted", key, cipher, compression, '%s.gpg' % msg)
    return get_file(fn)

def get_pgp_key(namespace, algo):
    fn = os.path.join("keys", "key.%s.%s.gpg" % (namespace, algo))
    return get_file(fn)

def get_all_keys():
    """
        Get dictionary of {key_id:key} for all keys in the tests/data/keys folder
        Memoized in the cached dictionary
    """
    if 'keys' not in cached:
        keys = {}
        key_folder = os.path.join(this_folder, '..', 'data', 'keys')
        for key_name in os.listdir(key_folder):
            location = os.path.join(key_folder, key_name)
            if os.path.isfile(location) and key_name.endswith("gpg"):
                with open(location, 'r') as k:
                    key = Key(passphrase="blahandstuff").parse(k.read())
                    keys.update(key.key_dict())
        cached['keys'] = keys
    return cached['keys']
