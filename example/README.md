# Cryptopyutils Examples

The following scripts and examples are showing the capabilities of cryptopyutils.

## List of examples

### CLI Scripts
/cli folder

#### sshkeygenpair.py : openSSH key pair generator CLI
This script is a basic CLI in the spirit of ssh-keygen.
By default:
- It generates user files (id_[alg] and id_[alg].pub). With the option -s, it can generate host files (ssh_host_*).
- It generate a 4096 bits RSA keypair in your user .ssh directory

Usage:
-t SSH key algorithm: RSA, ED25519, ECDSA, DSA
-c comment, unique name key identifier, typically user@host
-b Bits (RSA key_size or EC curve length)
-d Output directory.
-s generates ssh host files (generates ssh_host_* files instead of id_*)
--force forces existing files overwritting
-p Pword to encrypt the private key

Example 1: generate a default 4096 bits RSA keypair in your user directory
``sh
python sshkeygenpair.py -c root@example.com
``

Example 1: generate a 2048 bits RSA keypair in the ~/mydir folder with overwriting rights
``sh
python sshkeygenpair.py -t rsa -b 2048 -c root@example.com  -d ~/mydir --force
``

Example 2: generate a ED25519 file keypair with as pword
``sh
python sshkeygenpair.py -t ed25519 -c root@example.com -d ~/mydir -p
``

#### askpgen.py : Asymmetric key pair generator CLI
This script generates an asymmetric key pair (private key, public key).

The key are generated in PEM format

By default, it generates the keys in the /tmp/keys directory using a 4096 bits RSA algorithm.

Usage:
-n Key name (usually your FQDN www.example.com)
-a Key algorithm : rsa, ed25519, ed448, ecdsa, dsa
-d Output directory
-b Bits (RSA or DSA key size)
-c Elliptic Curve name (by default SECP384R1): Other curves are found in the cryptopyutils.utils file.
-p Pword to encrypt the private key
--force forces existing files overwritting

Example 1 : generate a 4096 bits RSA keypair

``sh
python askpgen.py -n www.example.com
``

Example 2 : generate a 2048 bits RSA keypair in a ~/mykeys directory with overwriting rights

``sh
python askpgen.py -n www.example.com -a rsa -b 2048 -d ~/mykeys --force
``

Example 3 : generate a ECDSA keypair with SECP521R1

``sh
python askpgen.py -n www.example.com -a ecdsa -c SECP521R1 -d ~/mykeys --force
``

Example 4: generate a 4096 bits RSA keypair with a pword

``sh
python askpgen.py -n www.example.com -p
``

#### selfsignedgen.py : Self-signed x509 Certificate generator CLI
The configuration file certconfig.yaml contains the subject details, your server DNS Names and IP addresses.

Usage:
-f is the path to the private key
-n is the unique name of the certificate
-y is the csr configuration file (YAML format)
-D is the output directory
--force forces existing files overwritting

Example :
``sh
python selfsignedgen.py -f ../others/keys/rsa_priv.pem -n www.example.com -y certconfig.yaml -D /tmp/test
``

#### csrgen.py : x509 Certificate Signing Request (CSR) generator CLI
The configuration file certconfig.yaml contains the subject details, your server DNS Names and IP addresses.

Usage:
-f is the path to the private key
-n is the unique name of the CSR
-y is the csr configuration file (YAML format)
-c is the shared challenge pword between the issuer and the subject
-D is the output directory
--force forces existing files overwritting

Example :
``sh
python csrgen.py -f ../others/keys/rsa_priv.pem -n www.example.com -y certconfig.yaml -c blabla -D /tmp/test
``
#### Passwords

WARNING : DO NOT USE THE -a option ON PRODUCTION SERVERS.
SECRETS WOULD BE STORED in various places, including /proc, process list (ps), logs(/var/log) and in the user's history list.

##### pwdenc.py : Password encryption CLI

This script encrypts a password and returns the salt and key.
Usage:
-p Normal mode with a password prompt
-a API mode: the password is provided in the terminal. VERY INSECURE as can be recorded in various places.

Example 1 : Normal code
``sh
python pwdenc.py -p
``

Example 2 : API mode
``sh
python pwdenc.py -a mypasswordtoencrypt
>>PWDENC WfQF0w3uobCwLjLirbwXcf5Jg3vELeAK7boQ1g/KQ/Y= 4zwIqwBFDoIsDHxxUC4trw==
``
In API mode: returns PWDENC, the key and salt in BASE64 separated by a space. The salt and key will change at each iteration.

##### pwdverif.py : Password verification CLI

This script verifies a tentative password against the salt and key.

Usage:
-p Normal mode with a password prompt
-a API mode: the password is provided in the terminal. VERY INSECURE as can be recorded in various places.
-s Salt (Base64 format)
-k Key (Base64 format)

In API mode, returns PWDVERIF and the test result with a space separation.

Example 1 : Normal code
``sh
python pwdverif.py -k WOzrVVioe2D8CDEh/6+zeTA1NXaN7v1st/JmdcTGHuQ= -s RSGGuZfbtL/uUl1IBoZm+A== -p
``
Example 2 : API mode
``sh
python pwdverif.py -k WOzrVVioe2D8CDEh/6+zeTA1NXaN7v1st/JmdcTGHuQ= -s RSGGuZfbtL/uUl1IBoZm+A== -a test
>>PWDVERIF True
``

#### consttimecomp : CLI to compare two strings (converted as bytes) with a constant time function to prevent timing attacks
Compare left and right items
example:
``sh
python consttimecomp.py left right
``

#### dirs.py : CLI for directory manipulation - create a directory structure similar to /etc/ssl, create and remove non-sytem, non-user directory
- To create a directory structure similar to /etc/ssl
``sh
python dirs.py ssldir /tmp/test
``
- To create a directory
``sh
python dirs.py mkdir /tmp/test
``
- To remove a directory
``sh
python dirs.py rmdir /tmp/test
``

### Other examples
/others folder

- asymsignverify.py: How to sign and verify messages or digests with private and public keys
- files.py : Files and filepaths manipulations
- rsaencdec.py : How to encrypt and decrypt messages using RSA

## Sample keys
/others/keys folder
