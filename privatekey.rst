#####################
Private Key : How to
#####################

************************************
Instantiate a private key object
************************************

With the configuration defaults:

.. code-block:: python

    from cryptopyutils.privatekey import PrivateKey
    # create the PrivateKey object with the configuration defaults
    privk = PrivateKey()

or with your own configuration:

.. code-block:: python

    from cryptopyutils.privatekey import PrivateKey
    from cryptopyutils.config import PrivateKeyCconfig
    myconfig = PrivateKeyCconfig()
    # you can then modify your configuration

    # create the PrivateKey object with your configuration
    privk = PrivateKey(config=myconfig)

*************************
Generate a private key
*************************

.. code-block:: python

    privk.gen()
    # alternative: generate an ED25519 key
    # privk.gen("ED25519")

**************************
Save a private key
**************************

.. code-block:: python

    filepath = "/tmp/myexample.com.pem"
    privk.save(filepath)

    >> True

If saved it returns True, otherwise False.

**********************
Load a private key
**********************

.. code-block:: python

    filepath = "/tmp/myexample.com.pem"
    privk.load(filepath)

***********************************************
Display the private key in PEM PKCS8 format
***********************************************

.. code-block:: python

    print(privk.keytext)

***************************************
Sign a message with your privatekey
***************************************

.. code-block:: python

    message = b'my message to sign'
    signature = privk.sign(message)
    # print the signed message
    print(signature)

Example of output:

.. code-block:: python

    >>b'638QWTOjdT712NOmpPi+nLBGdZ6zQ64+ZNQcOTSpyZDQv7k3mO4piHNNVHxz7L3scQgThcp1QBQR7fyrAep7Ys2ozB6bAvCI6wUSF8achgTt69HY...'

*******************************************
Decrypt a message with your private key
*******************************************

RSA is the encryption / decryption technique supported by cryptopyutils.

This example assumes you already have loaded your private key.

.. code-block:: python

    #load the cipher text (this case is invalid)
    ciphertext = b'e83JOPUT7e6syGGoJeAyU128cde0Ck4V7/lwo+0OHu/SXB2N/e5/JEdTdvbUY+j8...'

    #decrypt
    plaintext = privk.decrypt(ciphertext)

    #print the decrypted message
    print(ciphertext)

    >> b'my message to encrypt'
