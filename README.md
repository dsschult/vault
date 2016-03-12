# vault

A `cryptography`-based password store. Or really any text-like objects.

## Install

Installation is simple:

    git clone https://github.com/dsschult/vault.git

Then run it with `python3 vault.py`, using the various options.

## Why python 3?

Because python 3 been around for a while now, and the only way
to truly convert the masses is to stop writing python 2 code.
So I'm doing just that.

## Why `cryptography`?

So someone else does all the hard security work.
[`cryptography`](https://cryptography.io) is designed to be a
"cryptographic standard library" for python.

Even the encrypt and decrypt functions are taken directly
from their sample code, so it works as intended.

## Why can't it do X, Y, Z?

Because of the [KISS principle](https://en.wikipedia.org/wiki/KISS_principle).
Keeping it simple means it does the one thing it was designed for well.
