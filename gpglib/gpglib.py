from Crypto.PublicKey import RSA

from structures import EncryptedMessage, SecretKey

if __name__ == '__main__':
    key = RSA.importKey(open('../tests/data/gpg/key.asc').read())
    keys = {5524596192824459786: key}
    
    data = open('../tests/data/data.small.dump.gpg').read()
    message = EncryptedMessage(data, keys)
    message.decrypt()

    print "Message successfully decrypted data.dump::"
    print message.plaintext

    data = open('../tests/data/data.big.dump.gpg').read()
    message = EncryptedMessage(data, keys)
    message.decrypt()

    print "Message successfully decrypted data.big.dump::"
    print message.plaintext

    data = open('../tests/data/secret_key.gpg').read()
    message = SecretKey(data)
    keys = message.parse_keys()

    print "Message successfully parsed secret_key.gpg::"
    print keys
