#!/usr/bin/env python
"""
    Naive benchmark
    Where the keyword is naive
"""

from base import get_decryptor_and_message, start_loop
import multiprocessing
import argparse

def get_parser():
    parser = argparse.ArgumentParser(description='Naive Benchmark')
    parser.add_argument("-n", "--number-processes"
        , type = int
        , help = "The number of processes to be decrypting with"
        , default = 1
        , required = False
        )

    return parser

if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()
    loop_kwargs = dict(
          key_location = "tests/data/key.secret.gpg"
        , message_location = 'tests/data/data.small.dump.gpg'
        , passphrase = 'blahandstuff'
        )
    
    def run(key_location, message_location, passphrase):
        decryptor, message = get_decryptor_and_message(key_location, message_location, passphrase)
        decrypt_action = lambda : decryptor.decrypt(message)
        start_loop(decrypt_action)
    
    if args.number_processes == 0:
        print "Processed infinite messages in 0 seconds"
    
    elif args.number_processes == 1:
        run(**loop_kwargs)
    
    else:
        processes = []
        for _ in range(args.number_processes):
            process = multiprocessing.Process(target=run, kwargs=loop_kwargs)
            processes.append(process)
            process.start()
        
        try:
            for process in processes:
                process.join()
        except KeyboardInterrupt:
            print 'exiting'
