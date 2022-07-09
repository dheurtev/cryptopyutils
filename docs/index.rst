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

cryptopyutils can be used to :

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

***************
How to install
***************

Requirements
=============

This library requires python `cryptography`, `distro` and `pyaml` (for the CLI examples)

.. code-block:: console

  $ pip install cryptography distro pyaml

`cryptography <cryptographyurl_>`_ uses openSSL as its backend engine.


Install the library
====================

.. code-block:: console

  $ pip install cryptopyutils


********
Licence
********
* ``cryptopyutils`` is free open source software. It is released under `the Apache 2.0 licence <https://www.apache.org/licenses/LICENSE-2.0>`_.
* You are free to incorporate the library and/or its CLI in your open-source or proprietary projects.

*********
Contents
*********

.. toctree::
   :maxdepth: 1

   Overview <readme>
   Features <features>
   CLI <cli>
   How to : private key <privatekey>
   How to : public key <publickey>
   How to : password <password>
   Other examples <others>
   Contributions & Help <contributing>
   License <license>
   Authors <authors>
   Changelog <changelog>
   Module Reference <api/modules>

******************
Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _toctree: https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html
.. _reStructuredText: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _references: https://www.sphinx-doc.org/en/stable/markup/inline.html
.. _Python domain syntax: https://www.sphinx-doc.org/en/master/usage/restructuredtext/domains.html#the-python-domain
.. _Sphinx: https://www.sphinx-doc.org/
.. _Python: https://docs.python.org/
.. _Numpy: https://numpy.org/doc/stable
.. _SciPy: https://docs.scipy.org/doc/scipy/reference/
.. _matplotlib: https://matplotlib.org/contents.html#
.. _Pandas: https://pandas.pydata.org/pandas-docs/stable
.. _Scikit-Learn: https://scikit-learn.org/stable
.. _autodoc: https://www.sphinx-doc.org/en/master/ext/autodoc.html
.. _Google style: https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings
.. _NumPy style: https://numpydoc.readthedocs.io/en/latest/format.html
.. _classical style: https://www.sphinx-doc.org/en/master/domains.html#info-field-lists
