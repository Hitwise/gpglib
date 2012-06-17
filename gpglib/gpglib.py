from Crypto.PublicKey import RSA
import bitstring

from structures import Info

if __name__ == '__main__':
    key = RSA.importKey(open('../tests/data/gpg/key.asc').read())
    message = open('../tests/data/data.dump.gpg').read()

    keys = {
        5524596192824459786: key,
    }
    
    bytes = bitstring.ConstBitStream(bytes=message)
    info = Info(keys, bytes)
    info.decrypt()
