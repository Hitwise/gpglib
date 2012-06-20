#!/usr/bin/env python
"""
    Naive benchmark
    Where the keyword is naive
"""

from base import start_loop
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
        , message_location = 'tests/data/data.big.dump.gpg'
        , passphrase = 'blahandstuff'
        )
    
    if args.number_processes == 0:
        print "Processed infinite messages in 0 seconds"
    
    elif args.number_processes == 1:
        start_loop(**loop_kwargs)
    
    else:
        processes = []
        for _ in range(args.number_processes):
            process = multiprocessing.Process(target=start_loop, kwargs=loop_kwargs)
            processes.append(process)
            process.start()
        
        try:
            for process in processes:
                process.join()
        except KeyboardInterrupt:
            print 'exiting'
