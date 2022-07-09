##################
Password : How to
##################

******************************
Instantiate a Password object
******************************

.. code-block:: python

    from cryptopyutils.password import Password
    pwd = Password()

**********************
Encrypt a password
**********************

When you encrypt a password, you will receive in return the encrypted password (key), as well as a salt.

A cryptographic salt is made up of random bits added to each password instance before its hashing.
Salts create unique passwords even if two users choose the same passwords.
Salts help us mitigate hash table attacks by forcing attackers to re-compute them using the salts for each user.

.. code-block:: python

        # Set the password.
        # It is insecure to hard code any password. It should be read from user input.
        password = "My secret password"
        # encrypt
        key, salt = pwd.derive(password)
        # you obtain the key and salt in base64 format.
        # print the salt
        print("Salt (base64) : %s " % (base64.b64encode(salt).decode("utf8")))
        # print the key
        print("Key (base64) : %s " % (base64.b64encode(key).decode("utf8")))
        # typically you will write your salt and key in a database

**********************
Verify a password
**********************

.. code-block:: python

        # Set the password to verify.
        # It is insecure to hard code any password. It should be read from user input.
        password_to_verify = "My strange password"
        # Set the key and the salt
        # Typically you will retrieve them from your database
        salt = ''
        key = ''
        # You decode the base64 salt and key
        saltb = base64.b64decode(salt.encode("utf8"))
        keyb = base64.b64decode(key.encode("utf8"))
        # You verify it against the password to verify
        verif = pwd.verify(password_to_verify, keyb, saltb)

        >> True

If True, the user is authenticated. False if not.
