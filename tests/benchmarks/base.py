"""Helpers for naive benchmark"""

import time
import sys
import os
    
def get_decryptor_and_message(key_location, message_location, passphrase):
    this_dir = os.path.dirname(__file__)
    master_dir = os.path.join(this_dir, '../../')
    sys.path = [master_dir] + sys.path

    from gpglib.structures import EncryptedMessage, Key
    
    # Parse the secret key
    secret_key_location = os.path.join(master_dir, key_location)
    key = Key(passphrase=passphrase).parse(open(secret_key_location).read())
    keys = key.key_dict()
    
    # Get message we're gonna continously decrypt
    message_location = os.path.join(master_dir, message_location)
    message = open(message_location).read()
    return EncryptedMessage(keys=keys), message

def start_loop(key_location, message_location, passphrase):
    decryptor, message = get_decryptor_and_message(key_location, message_location, passphrase)
    
    # Initial things
    count = 0
    total = 0
    start = time.time()
    last = start
    
    # Print stats every second
    # And print total stats on ctrl+c
    try:
        while True:
            # Decrypt again, increment count
            decryptor.decrypt(message)
            count += 1
            total += 1
            
            # Determine if it's been a second yet
            now = time.time()
            if now - last >= 1:
                print "%s messages per second" % count
                last = now
                count = 0
    
    except KeyboardInterrupt:
        end = time.time()
        seconds = end - start
        print "Decrypted %s messages in %.2f seconds (%.2f messages per second)" % (total, seconds, total/seconds)