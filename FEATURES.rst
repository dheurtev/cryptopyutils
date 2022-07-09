#########
Features
#########

``cryptopyutils`` implements the following features of ``cryptography``:
  * `implemented`_
  * `not tested <#nottested>`_
  * `not implemented <#notimplemented>`_

Defaults can be modified at run time by passing a configuration object (from config.py) at run time or by modifying the config.py file.

Example of passing a configuration object :

.. code-block:: python

    from cryptopyutils.privatekey import PrivateKey
    from cryptopyutils.config import PrivateKeyCconfig
    myconfig = PrivateKeyCconfig()
    # you can then modify your configuration

    # create the PrivateKey object with your configuration
    privk = PrivateKey(config=myconfig)


.. _implemented:

************
Implemented
************

Asymmetric encryption and decryption
=====================================

* RSA :

    * Default : 4096 bits
    * Padding : OAEP + MGF1 + SHA256

.. _signature:

Signature and Verification
===========================

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
======================================

* PBKDF2HMAC :

  * Key length : 32
  * Salt: 16 bytes (128 bits)
  * Hashing : SHA256
  * Iterations : 390000

Example: See example/password.py

Asymmetric keys and certificates encoding formats
===================================================

* PEM or DER private keys and public keys in PKCS8 (current SSL) or PKCS1 certificates (old style openSSL -legacy) language
* PEM or DER x509 CSR and Certificates
* OpenSSH key pairs (private key with PEM, public key in OpenSSH format) with RSA, ED25519, ECDSA and DSA (legacy)

Constant time function
=======================
Example: See example/consttimecomp.py



.. _nottested:

*****************************
Implemented but not tested
*****************************

* None



.. _notimplemented:

****************************
Not implemented (wish list)
****************************

* Encoding:

  * RAW
  * X962
  * SMIME

* Formats:

  * PKCS7
  * PKCS12

* SSH Certificates
* x509 Certificate Revokation List (CRL)
* Key exchange :

  * X25519,
  * X448,
  * Diffie-Hellman key exchange (ECDH, DH)

* Two-factor authentication
* Symmetric encryption
* MAC/HMAC
* Fernet
* Advanced SSL certificate features, extensions
* ...
