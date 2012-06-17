from Crypto.PublicKey import RSA
import bitstring

from structures import Message

if __name__ == '__main__':
    key = RSA.importKey(open('../tests/data/gpg/key.asc').read())
    keys = {5524596192824459786: key}
    
    data = open('../tests/data/data.dump.gpg').read()
    bytes = bitstring.ConstBitStream(bytes=data)
    
    message = Message(keys, bytes)
    message.decrypt()
