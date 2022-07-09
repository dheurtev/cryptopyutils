.. image:: https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold
    :alt: Project generated with PyScaffold
    :target: https://pyscaffold.org/

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :alt: Style follow black
    :target: https://github.com/psf/black

.. _cryptographyurl: https://cryptography.io/en/latest/

##############
cryptopyutils
##############

High-level Python3 cryptography library using `cryptography <cryptographyurl_>`_ with sensible configurable defaults and CLI scripts.

``cryptopyutils`` can be used to :

* encrypt ("derive") and verify passwords.
* generate, save and load Asymmetric encryption keys and certificates : 
  
  * private keys/public keys (RSA, ED25519, ECDSA, DSA, etc).
  * generate, save and load x509 Certificate Signing Request (CSR).
  * generate, save and load x509 Certificates, particularly self-signed certificates, to be used in SSL applications.

* encrypt or decrypt messages with RSA.
* sign and verify messages with asymetric encryption. It works with small messages or in digest mode.
* perform constant time comparisons between two series of bytes (prevents timing attacks).

Please provide feedback to `@dheurtevent1`_.

.. _@dheurtevent1: http://twitter.com/dheurtevent1


***********
Disclaimer
***********

.. caution:: USE AT YOUR OWN RISK. Has been tested only on Ubuntu 20.04 (Linux) with python 3.9.12.

****************
How to install
****************

Requirements
=============

This library requires python ``cryptography``, ``distro`` and ``pyaml`` (for the CLI examples)

.. code-block:: console

  $ pip install cryptography distro pyaml


`cryptography <cryptographyurl_>`_ uses openSSL as its backend engine.


Install the library
======================

.. code-block:: console

  $ pip install cryptopyutils


.. _usage:

******
Usage
******

* ``cryptopyutils`` is free open source software. It is released under `the Apache 2.0 licence <https://www.apache.org/licenses/LICENSE-2.0>`_.
* You are free to incorporate the library and/or its CLI in your open-source or proprietary projects.

**To use the library**

You can read the following how to guides:

* `How to : private key <https://cryptopyutils.readthedocs.io/en/latest/privatekey.html>`_
* `How to : public key <https://cryptopyutils.readthedocs.io/en/latest/publickey.html>`_
* `How to : password <https://cryptopyutils.readthedocs.io/en/latest/password.html>`_

You can also read the source code of other examples.
  
In addition, you can have a look at the `API <https://cryptopyutils.readthedocs.io/en/latest/api/modules.html>`_ and at the source code
in the `Github repository <https://github.com/dheurtev/cryptopyutils>`_.

**To use the CLI examples**

You can have a look at the CLI page.

***************************
Code quality and stability
***************************

* The code is documented, tested (>70 tests) and provided with examples.
* Defaults can be provided at run time by developers or can be modified in the config.py file. 
* The default values use the NIST recommendations and recommendations of the `cryptography` packages, as well as :

  * https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
  * https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022
  * https://www.keylength.com/en/4/

* `cryptopyutils` has a goal of strong API stability policy: 
  
  * Public API shall not be removed or renamed without providing a compatibility alias. 
  * The behavior of existing APIs shall not change. 
  * Exceptions to API stability are for security purposes to resolve security issues or harden the library against a possible attack or underlying changes in `cryptography`.

