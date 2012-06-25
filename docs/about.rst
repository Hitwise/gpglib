.. _about:

Purpose
=======

This library was made with a particular need in mind and hence does the bare minimum to achieve that:

 * Parse PGP RSA Secret Keys
 * Decrypt CAST5 encrypted, ZIP compressed PGP messages
 
It provides a simple interface to do this with (see :ref:`examples`) and done with a readable/understandable implementation.

Some Background
===============

This library was created out of frustration with how slow the python libraries for parsing PGP messages were. 

As it turns out, all the other libraries (except one) do their work by shelling out to the ``gpg`` binary. Our requirements were to process a large number of small PGP messages and ideally without batching them. With the existing libraries we were only getting around 20 messages a second due to the overhead of shelling out to gpg.

The one library we found that didn't shell out was a magnificent thing called OpenPGP, which can be found over at http://pypi.python.org/pypi/OpenPGP. Unfortunately this library was last edited 7 years ago and is about as slow as shelling out.

We decided that we could do better and so started our own RFC4880 compliant PGP parser.

Some initial tests show that gpglib can get around 300 messages a second (when pycrypto is compiled with fast math).

References
==========

We mainly used the following references to make this parser:

 * RFC4880 (http://tools.ietf.org/html/rfc4880)
 * OpenPGP (http://pypi.python.org/pypi/OpenPGP)
 * OpenPGP SDK (http://openpgp.nominet.org.uk/cgi-bin/trac.cgi)
 * Python pgpdump (http://pypi.python.org/pypi/pgpdump/1.3)
 * C pgpdump (http://www.mew.org/~kazu/proj/pgpdump/en/)
 * libsimplepgp (https://github.com/mrmekon/libsimplepgp)

Libraries
=========

This library isn't possible without:

 * Pycrypto (https://www.dlitz.net/software/pycrypto/)
 * Bitstring (http://packages.python.org/bitstring/)
