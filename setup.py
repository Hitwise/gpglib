from setuptools import setup, find_packages

setup(
      name = "gpglib"
    , version = "0.1.0"
    , packages = find_packages()
    , install_requires =
      [
      ],

    # metadata for upload to PyPI
    , author = "Hitwise"
    , author_email = "nobody@hitwise.com"
    , description = "Library for decrypting gpg that doesn't shell out to gpg"
    , license = "Other/Proprietary"
    , keywords = "gpg decrypt"
    )
