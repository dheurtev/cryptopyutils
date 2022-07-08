# -*- coding: utf-8 -*-
"""password.py - Password : derive, verify

Class:

* Password

https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/

"""
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import config
from . import utils


class Password:
    """Password Management Object"""

    def __init__(self, conf=config.PasswordConfig()):
        """Password init
        Args:
            conf (config.PasswordConfig, optional): An instance of PasswordConfig.

        """
        self.conf = conf

    def gen_salt(self, length=16):
        """Generate a salt

        Args:
            length (int, optional): Length of the salt.
                Defaults to 16.

        Returns:
            bytes: salt

        """
        return os.urandom(int(length))

    def derive(self, password):
        """Generate a password using the PDKDF2 algorithm

        Args:
            password (bytes or str) : the password. Bytes or string.
                If string, encoded in UTF-8.

        Returns:
            bytes: The derived key.
            bytes: The salt.

        """
        # generate the salt
        salt = self.gen_salt(self.conf.salt_length)
        # prepare the cipher
        kdf = PBKDF2HMAC(
            algorithm=utils.hash_algorithm(self.conf.hash_algorithm),
            length=self.conf.key_length,
            salt=salt,
            iterations=self.conf.iterations,
        )
        # prepare the password
        if isinstance(password, str):
            encoded_password = password.encode("utf-8")
        else:
            encoded_password = password
        key = kdf.derive(encoded_password)
        return key, salt

    def verify(self, attempt, key, salt):
        """Verify a password using the PDKDF2 algorithm

        Args:
            attempt (bytes or str) : the tentative password to be checked.
                If string, encoded in UTF-8.
            key (bytes): The key.
            salt (bytes): The salt.

        Returns:
            bool: True if verified, False if not verified

        """
        # prepare the cipher
        kdf = PBKDF2HMAC(
            algorithm=utils.hash_algorithm(self.conf.hash_algorithm),
            length=self.conf.key_length,
            salt=salt,
            iterations=self.conf.iterations,
        )
        # prepare the tentative password
        if isinstance(attempt, str):
            attempt_password = attempt.encode("utf-8")
        else:
            attempt_password = attempt
        # verify
        try:
            kdf.verify(attempt_password, key)
            return True
        except InvalidKey:
            return False
