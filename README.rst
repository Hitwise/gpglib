GPG Lib
=======

We couldn't find a library for decrypting gpg that didn't shell out to gpg.

And shelling out to gpg is slow when you do it for many small files.

So, with the help of http://pypi.python.org/pypi/OpenPGP and PyCrypto we created this, which is more performant than shelling out....

Installing
==========

To install, just use pip::

    $ pip install gpglib

Or download from pypi: http://pypi.python.org/pypi/gpglib.

Or clone the git repo: https://github.com/Hitwise/gpglib.

Making test data
================

This is what I did to get the data in tests/data.

From within tests/data::

    $ gpg --gen-key --homedir ./gpg
    # Once with RSA encrypt and sign, username Stephen and password "blahandstuff"
    # And again with DSA/Elgamal, username Bobby and password "blahandstuff"

Then find the keyid::

    $ gpg --homedir ./gpg --list-keys
        #     ./gpg/pubring.gpg
        # -----------------
        # pub   2048R/1E42B68C 2012-06-15
        # uid                  Stephen
        # sub   2048R/80C7020A 2012-06-15
    # Here, the key we want is "80C7020A"
    
Then with that keyid export the secret and public keys for both the rsa and dsa keys:

    $ gpg --export 80C7020A > key.public.rsa.gpg
    $ gpg --export-secret-key 80C7020A > key.secret.rsa.gpg

I then created dump.small and dump.big as random json structures (the big on is from http://json.org/example.html).

Then used the following command to populate the tests/data/encrypted folder:
    
    $ gpg -o encrypted/<key>/<cipher>/<compression>/<msg>.gpg --cipher-algo <cipher> --compress-algo <compression> --yes --disable-mdc --homedir ./gpg -r <name for key> --encrypt dump.<msg>

Where:

 * <key> is rsa or dsa
 * <cipher> is cast5, aes or blowfish
 * <compression> is zip, zlib or bzip2
 * <msg> is small and big for the two examples I have

Tests
=====

Install the pip requirements::

    $ pip install -r requirements_test.txt

Install nosy if you want the ability to make tests autorun when you run the tests (https://bitbucket.org/delfick/nosy)

And then run::

    $ ./test.sh

Or if you have nosy::

    $ nosy ./test.sh

Currently not much is tested.

Docs
====

Install the pip requirements::

    $ pip install -r requirements_docs.txt

And then go into the docs directory and run make::

    $ cd docs
    $ make html

Open up docs/_build/html/index.html in your browser.

Automatically generated documentation is available at: http://gpglib.readthedocs.org/en/latest/
