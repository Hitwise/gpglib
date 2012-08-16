from setuptools import setup, find_packages

# All the packages except test
packages = [pkg for pkg in find_packages() if not pkg.startswith('tests')]

setup(
      name = "gpglib"
    , version = "0.1.1"
    , packages = packages
    , install_requires =
      [ 'pycrypto'
      , 'bitstring'
      ]

    # metadata for upload to PyPI
    , author = "Hitwise"
    , author_email = "nobody@hitwise.com"
    , description = "Library for decrypting gpg that doesn't shell out to gpg"
    , license = "LGPLv2"
    , keywords = "gpg decrypt"
    )
