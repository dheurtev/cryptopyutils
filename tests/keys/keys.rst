=====
Keys
=====

PEM keys examples
=================

This folder contains a sample of private and public key pairs, CRS and certificates encoded in the pem format.

Sources
==========

* The keys contained in the example/others/keys folder have been generated with crytopyutils except:

* digicert.crt file source: https://www.digicert.com/order/sample-csr.php

Website to Read a CSR file details
==================================
https://www.ssltools.eu/csr-viewer.html


Website to Read a Certificate file details
===========================================
https://www.sslchecker.com/certdecoder


To validate SSH public key fingerprints
========================================

.. code-block:: console

    $ ssh-keygen -l -f /tmp/tests/id_rsa.pub
