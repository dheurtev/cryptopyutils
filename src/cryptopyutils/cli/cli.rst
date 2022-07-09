=====================
List of CLI scripts
=====================

The following CLI scripts are showing how the `cryptopyutils` library can be implemented :

* :ref:`asymkpgencli`
* :ref:`sshkpgencli`
* :ref:`selfsignedcsrgencli`
* :ref:`passwordgencli`
* :ref:`consttimecompcli`
* :ref:`directoriescli`


.. _asymkpgencli:

Asymmetric key pair generator
------------------------------

askpgen.py : Asymmetric key pair generator CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This script generates an asymmetric key pair (private key, public key).

The key are generated in PEM format

**By default:**

* It generates the keys in the /tmp/keys directory using a 4096 bits RSA algorithm.

**Usage:**

* -n Key name (usually your FQDN www.example.com)
* -a Key algorithm : rsa, ed25519, ed448, ecdsa, dsa
* -d Output directory
* -b Bits (RSA or DSA key size)
* -c Elliptic Curve name (by default SECP384R1): Other curves are found in the cryptopyutils.utils file.
* -p password to encrypt the private key
* --force forces existing files overwritting

**Example 1 : generate a 4096 bits RSA keypair**

.. code-block:: console

  $ python askpgen.py -n www.example.com

**Example 2 : generate a 2048 bits RSA keypair in a ~/mykeys directory with overwriting rights**

.. code-block:: console

  $ python askpgen.py -n www.example.com -a rsa -b 2048 -d ~/mykeys --force

**Example 3 : generate a ECDSA keypair with SECP521R1**

.. code-block:: console

  $ python askpgen.py -n www.example.com -a ecdsa -c SECP521R1 -d ~/mykeys --force

**Example 4: generate a 4096 bits RSA keypair with a pword**

.. code-block:: console

  $ python askpgen.py -n www.example.com -p


.. _sshkpgencli:

SSH key pair generator
-----------------------

CLI scripts are contained in the /cli folder

sshkeypairgen.py : openSSH key pair generator CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This script is a basic CLI in the spirit of ssh-keygen.

**By default:**

* It generates user files (id_[alg] and id_[alg].pub). With the option -s, it can generate host files (ssh_host_*).
* It generate a 4096 bits RSA keypair in your user .ssh directory

**Usage:**

* -t SSH key algorithm: RSA, ED25519, ECDSA, DSA
* -c comment, unique name key identifier, typically user@host
* -b Bits (RSA key_size or EC curve length)
* -d Output directory.
* -s generates ssh host files (generates ssh_host_* files instead of id_*)
* --force forces existing files overwritting
* -p password to encrypt the private key

**Example 1: generate a default 4096 bits RSA keypair in your user directory**

.. code-block:: console

  $ python sshkeypairgen.py -c root@example.com


**Example 2: generate a 2048 bits RSA keypair in the ~/mydir folder with overwriting rights**

.. code-block:: console

  $ python sshkeypairgen.py -t rsa -b 2048 -c root@example.com  -d ~/mydir --force

**Example 3: generate a ED25519 file keypair with as pword**

.. code-block:: console

  $ python sshkeypairgen.py -t ed25519 -c root@example.com -d ~/mydir -p

.. _selfsignedcsrgencli:

Self-signed x509 Certificates and CSR
----------------------------------------

selfsignedgen.py : Self-signed x509 Certificate generator CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration file certconfig.yaml contains the subject details, your server DNS Names and IP addresses.

**Usage:**

* -f is the path to the private key
* -n is the unique name of the certificate
* -y is the csr configuration file (YAML format)
* -D is the output directory
* --force forces existing files overwritting

**Example :**

.. code-block:: console

  $ python selfsignedgen.py -f rsa_priv.pem -n www.example.com -y certconfig.yaml -D /tmp/test

**YAML configuration file**

See the certconfig.yaml file in the cli folder.

* The `dnsnames` field must contain the list of DNS Names for the certificate.
* The `ipaddresses` field must contain the list of IP addresses for the certificate.
* The `subject` field must contain the details of the server:

  * COMMON_NAME : the common name (typically your server's DNS name)
  * COUNTRY_NAME : the country (the ISO 2 letters country code)
  * LOCALITY_NAME : the city
  * STATE_OR_PROVINCE_NAME : the state or province (must be spelled out)
  * ORGANIZATION_NAME: the name of the organization

csrgen.py : x509 Certificate Signing Request (CSR) generator CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration file certconfig.yaml contains the subject details, your server DNS Names and IP addresses.

**Usage:**

* -f is the path to the private key
* -n is the unique name of the CSR
* -y is the csr configuration file (YAML format)
* -c is the shared challenge pword between the issuer and the subject
* -D is the output directory
* --force forces existing files overwritting

**Example :**

.. code-block:: console

  $ python csrgen.py -f rsa_priv.pem -n www.example.com -y certconfig.yaml -c blabla -D /tmp/test

**YAML configuration file**

See the certconfig.yaml file in the cli folder.

* The `dnsnames` field must contain the list of DNS Names for the certificate.
* The `ipaddresses` field must contain the list of IP addresses for the certificate.
* The `subject` field must contain the details of the server:

  * COMMON_NAME : the common name (typically your server's DNS name)
  * COUNTRY_NAME : the country (the ISO 2 letters country code)
  * LOCALITY_NAME : the city
  * STATE_OR_PROVINCE_NAME : the state or province (must be spelled out)
  * ORGANIZATION_NAME: the name of the organization

.. _passwordgencli:

Password encryption and verification
--------------------------------------

.. danger:: DO NOT USE THE -a option IN A PRODUCTION ENVIRONMENT.
    SECRETS WOULD BE STORED in various places, including /proc, process list (ps), logs(/var/log) and in the user's history list.

pwdenc.py : Password encryption CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This script encrypts a password and returns the salt and key.

**Usage:**

* -p Normal mode with a password prompt
* -a API mode: the password is provided in the terminal. VERY INSECURE as can be recorded in various places.

**Example 1 : Normal code**

.. code-block:: console

  $ python pwdenc.py -p

**Example 2 : API mode**

.. code-block:: console

  $ python pwdenc.py -a mypasswordtoencrypt

    >>PWDENC WfQF0w3uobCwLjLirbwXcf5Jg3vELeAK7boQ1g/KQ/Y= 4zwIqwBFDoIsDHxxUC4trw==

In API mode: returns PWDENC, the key and salt in BASE64 separated by a space. The salt and key will change at each iteration.

pwdverif.py : Password verification CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This script verifies a tentative password against the salt and key.

**Usage:**

* -p Normal mode with a password prompt
* -a API mode: the password is provided in the terminal. VERY INSECURE as can be recorded in various places.
* -s Salt (Base64 format)
* -k Key (Base64 format)

In API mode, returns PWDVERIF and the test result with a space separation.

**Example 1 : Normal code**

.. code-block:: console

  $ python pwdverif.py -k WOzrVVioe2D8CDEh/6+zeTA1NXaN7v1st/JmdcTGHuQ= -s RSGGuZfbtL/uUl1IBoZm+A== -p

**Example 2 : API mode**

.. code-block:: console

  $ python pwdverif.py -k WOzrVVioe2D8CDEh/6+zeTA1NXaN7v1st/JmdcTGHuQ= -s RSGGuZfbtL/uUl1IBoZm+A== -a test

    >>PWDVERIF True



.. _consttimecompcli:

Constant time comparison
-------------------------

consttimecomp : CLI to compare two strings (converted as bytes) with a constant time function to prevent timing attacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Compare the left and right strings (converted as bytes).

**Example :**

.. code-block:: console

  $ python consttimecomp.py left right


.. _directoriescli:

Directory creation and removal
-------------------------------

dirs.py : CLI for directory manipulation - create or remove a non-sytem, non-user directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**To create a directory**

.. code-block:: console

  $ python dirs.py mkdir /tmp/test

**To remove a directory**

.. code-block:: console

  $ python dirs.py rmdir /tmp/test
