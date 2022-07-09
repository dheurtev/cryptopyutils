#########################
Publickey Key : How to
#########################

************************************
Instantiate a public key object
************************************

With the configuration defaults:

.. code-block:: python

    from cryptopyutils.publickey import PublicKey
    # create the PublicKey object with the configuration defaults
    pubk = PublicKey()

or with your own configuration:

.. code-block:: python

    from cryptopyutils.publickey import PublicKey
    from cryptopyutils.config import PublicKeyCconfig
    myconfig = PublicKeyCconfig()
    # you can then modify your configuration

    # create the PublicKey object with your configuration
    pubk = PublicKey(config=myconfig)

************************************
Generate a public key
************************************

Prior to the generation of a public key we must create or load a private key.

Example : loading a private key

.. code-block:: python

    from cryptopyutils.privatekey import PrivateKey
    privk_filepath = "/tmp/myexample.com.pem"
    privk = PrivateKey()
    privk.load(filepath)

.. code-block:: python

    from cryptopyutils.publickey import PublicKey
    # create the PublicKey object with the configuration defaults
    pubk = PublicKey(private_key=privk)
    # generate the RSA public key
    pubk.gen()
    # alternative: generate use ED25519 private key
    # pubk.gen("ED25519")

************************************
Save the public key
************************************

.. code-block:: python

    pubk_filepath = "/tmp/myexample.com.pub"
    pubk.save(pubk_filepath)

    >> True

If saved it returns True, otherwise False.

***********************
Load the public key
***********************

.. code-block:: python

    pubk_filepath = "/tmp/mykey/myexample.com.pub"
    pubk.load(pubk_filepath)


**********************************************
Display the public key in PEM PKCS8 format
**********************************************

.. code-block:: python

    print(pubk.keytext)

******************************************
Verify a message with your public key
******************************************

This example assumes you already have loaded your public key.

.. code-block:: python

    #Copy a valid signature (this one is invalid)
    signature = b'638QWTOjdT712NOmpPi+nLBGdZ6zQ64+ZNQcOTSpyZDQv7k3mO4piHNNVHxz7L3scQgThcp1QBQR7fyrAep7Ys2ozB6bAvCI6wUSF8achgTt69HY...'
    message_to_verify = b'my message to sign'
    # Verify
    verif = pubk.verify(signature, message_to_verify)

    >> True

If verified it returns True, otherwise False.

******************************************
Encrypt a message with your public key
******************************************

RSA is the encryption / decryption technique supported by cryptopyutils.

This example assumes you already have loaded your public key.

.. code-block:: python

    # Choose the message to encrypt
    message_to_encrypt = b'my message to encrypt'
    # Encrypt
    ciphertext = pubk.encrypt(message_to_encrypt)
    # print the message
    print(ciphertext)

    >>  b'e83JOPUT7e6syGGoJeAyU128cde0Ck4V7/lwo+0OHu/SXB2N/e5/JEdTdvbUY+j8...'
