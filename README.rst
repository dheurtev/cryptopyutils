.. image:: https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold
    :alt: Project generated with PyScaffold
    :target: https://pyscaffold.org/

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black



|

=============
cryptopyutils
=============


High-level library using Python `cryptography` with sensible defaults.

cryptopyutils can be used to :
- encrypt ("derive") and verify passwords,
- generate, save and load Asymmetric encryption keys : private keys/public keys (RSA, ED25519, ECDSA, DSA, etc),
- encrypt or decrypt messages with RSA,
- sign and verify messages with asymetric encryption (works with small messages or in digest mode),
- generate, save and load x509 Certificate Signing Request (CSR),
- generate, save and load x509 Certificates, particularly self-signed certificates, to be used in SSL applications.

Note: `cryptography` uses openSSL as its backend engine.

## Requires python cryptography:
```py
pip install cryptography
```

## Install the library
```py
pip install cryptopyutils
```

## Usage
See the [example]() directory.

## Tests
See the [test]() directory.

## Licence : MIT

## Details

### Asymmetric encryption and decryption
- RSA (default 4096 bits) with padding OAEP + MGF1 + SHA256

### Signature and Verification
- RSA (default 4096 bits)+ PSS + MGF1 + Hashing SHA256
- Elliptic Curve (default SECP384R1) with ECDSA (Hashing SHA 256)
- ED25519
- ED448
- DSA (legacy, default 1028 bits) + PSS + MGF1

### Passwords encryption and verification
- PBKDF2HMAC (Defaults: Salt: 16 bytes (128 bits) + Hashing SHA256 + key length 32 + iterations 390000
Example: See example/password.py

### Keys and certificates encoding formats
- PEM
- DER
- SSH (openSSH): RSA, ED25519, ECDSA, DSA (legacy)
- PKCS8 certificates (current SSL)
- PKCS1 (old style openSSL -legacy)

### Constant time functions
Example: See example/constant_time_comparison.py

## Implemented but not tested
- RAW (not tested)
- X962 (not tested)
- SMIME (not tested)

## Not implemented
- SSH Certificates
- x509 Certificate Revokation List (CRL)
- Key exchange : X25519, X448, Diffie-Hellman key exchange (ECDH, DH)
- Two-factor authentication
- Symmetric encryption
- MAC/HMAC
- Fernet
- Advanced SSL certificate features
...

### Code Quality
- The code is documented, tested (>70 tests) and provided with examples.
- Defaults can be modified in the config.py and in the utils.py files if needed.
- The default values use the NIST recommendations and recommendations of the `cryptography` packages, as well as :
[https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html](https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html)
[https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022](https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/)
[https://www.keylength.com/en/4/](https://www.keylength.com/en/4/)
- Expected coding style is as compliant as possible with PEP8 (use flake8, pylint, etc).
- Use single quotes whereever possible.
- `cryptopyutils` has a goal of strong API stability policy: Public API shall not be removed or renamed without providing a compatibility alias. The behavior of existing APIs shall not change. Exceptions to API stability are for security purposes to resolve security issues or harden the library against a possible attack or underlying changes in `cryptography`.

## Disclaimer
- Has been tested only on Ubuntu 20.04 with python 3.9.12.
- USE AT YOUR OWN RISK.

## Contributions
- Contributions and code reviews are welcome.
- Feedback, bug reports, documentation, additional tests and tests on other distribution and platforms are welcome.
- Implementation of the missing feature is welcome, provided tests and examples are provided at the same time.

.. _pyscaffold-notes:

Note
====

This project has been set up using PyScaffold 4.2.3. For details and usage
information on PyScaffold see https://pyscaffold.org/.
