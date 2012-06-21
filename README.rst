GPG Lib
=======

We couldn't find a library for decrypting gpg that didn't shell out to gpg.

And shelling out to gpg is slow when you do it for many small files.

So, with the help of http://pypi.python.org/pypi/OpenPGP and PyCrypto we created this, which is more performant than shelling out....

Installing
==========

To install, just use pip::

    $ pip install gpglib

Or download from pypi, http://pypi.python.org/pypi/gpglib.

Making test data
================

This is what I did to get the data in test.data.

Inside tests/data::

    $ gpg --gen-key --homedir ./gpg
    # I gave it all default options, username Stephen and password "blahandstuff"

Then find the keyid::

    $ gpg --homedir ./gpg --list-keys
        #     ./gpg/pubring.gpg
        # -----------------
        # pub   2048R/1E42B68C 2012-06-15
        # uid                  Stephen
        # sub   2048R/80C7020A 2012-06-15
    # Here, the key we want is "80C7020A"
    
Then with that keyid export the secret and public keys:

    $ gpg --export 80C7020A > key.public.gpg
    $ gpg --export-secret-key 80C7020A > key.secret.gpg

I then created data.small.dump and data.big.dump as random json structures (the big on is from http://json.org/example.html) and did the following to make the encrypted .gpg equivalent::
    
    $ gpg -o data.dump.gpg --cipher-algo CAST5 --compress-algo ZIP --yes --disable-mdc --homedir ./gpg  -r Stephen --encrypt data.dump

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
