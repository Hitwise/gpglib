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

def get_encrypted(namespace):
    return get_file("data.%s.dump.gpg" % namespace)

def get_rsa_key(name):
    return RSA.importKey(get_file(name))
    
def get_rsa_keys():
    return {5524596192824459786 : get_rsa_key("gpg/key.asc")}
