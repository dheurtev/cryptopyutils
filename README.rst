.. image:: https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold
    :alt: Project generated with PyScaffold
    :target: https://pyscaffold.org/

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. _cryptographyurl:https://cryptography.io/en/latest/

|
=============
cryptopyutils
=============

High-level cryptography library using Python `cryptography <cryptographyurl_>`_ with sensible configurable defaults.

cryptopyutils can be used to :

* encrypt ("derive") and verify passwords.
* generate, save and load Asymmetric encryption keys : private keys/public keys (RSA, ED25519, ECDSA, DSA, etc).
* encrypt or decrypt messages with RSA.
* sign and verify messages with asymetric encryption. It works with small messages or in digest mode.
* generate, save and load x509 Certificate Signing Request (CSR).
* generate, save and load x509 Certificates, particularly self-signed certificates, to be used in SSL applications.

Please provide feedback to `@dheurtevent1`_.

.. _@dheurtevent1: http://twitter.com/dheurtevent1

Note: `cryptography` uses openSSL as its backend engine.

How to install
==============

Requirements
------------

This library requires python `cryptography`, `distro` and `pyaml` (for the CLI examples)

.. code::shell-session
pip install cryptography distro pyaml

Install the library
-------------------

.. code::shell-session
pip install cryptopyutils

Details
=======
Asymmetric encryption and decryption
------------------------------------
* RSA :

    * Default : 4096 bits
    * Padding : OAEP + MGF1 + SHA256

Signature and Verification
--------------------------
* RSA :

    * Default : 4096 bits
    * Padding : PSS + MGF1 + SHA256

* Elliptic Curve
   
    * Default : SECP384R1
    * Padding : ECDSA + Hashing SHA-256
  
* ED25519
* ED448
* DSA (legacy) :

  * Default : 1024 bits
  * PSS + MGF1

Passwords encryption and verification
-----------------------------------------
* PBKDF2HMAC : 

  * Key length : 32 
  * Salt: 16 bytes (128 bits)
  * Hashing : SHA256 
  * Iterations : 390000

Example: See example/password.py

Keys and certificates encoding formats
--------------------------------------
* PEM
* DER
* SSH (openSSH): RSA, ED25519, ECDSA, DSA (legacy)
* PKCS8 certificates (current SSL)
* PKCS1 (old style openSSL -legacy)

Constant time function
-----------------------
Example: See example/consttimecomp.py

Implemented but not tested
--------------------------
* RAW (not tested)
* X962 (not tested)
* SMIME (not tested)

Not implemented
---------------
* SSH Certificates
* x509 Certificate Revokation List (CRL)
* Key exchange : X25519, X448, Diffie-Hellman key exchange (ECDH, DH)
* Two-factor authentication
* Symmetric encryption
* MAC/HMAC
* Fernet
* Advanced SSL certificate features, extensions
* ...

Usage
=====
See the [example]() directory.

Tests
=====
See the [test]() directory.

Licence
=======
Apache 2.0

Code Quality
============
* The code is documented, tested (>70 tests) and provided with examples.
* Defaults can be modified in the config.py file.
* The default values use the NIST recommendations and recommendations of the `cryptography` packages, as well as :

  * https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
  * https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022
  * https://www.keylength.com/en/4/

* `cryptopyutils` has a goal of strong API stability policy: Public API shall not be removed or renamed without providing a compatibility alias. The behavior of existing APIs shall not change. Exceptions to API stability are for security purposes to resolve security issues or harden the library against a possible attack or underlying changes in `cryptography`.

Disclaimer
==========
* Has been tested only on Ubuntu 20.04 with python 3.9.12.
* **USE AT YOUR OWN RISK.**


.. _pyscaffold-notes:

Note
====
- This project has been set up using PyScaffold 4.2.3. For details and usage information on PyScaffold see https://pyscaffold.org/.
