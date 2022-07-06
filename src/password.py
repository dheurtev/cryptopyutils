# -*- coding: utf-8 -*-
"""password.py - Password : derive, verify

Class:
- Password

https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/

"""
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import utils
from ..old.cryptopyutils import config


class Password:
    """Password Managemeng Object"""

    def __init__(
        self,
        hash_algorithm=config.DEFAULT_HASH_ALG,
        salt_length=config.DEFAULT_PWD_SALT_LENGTH,
        length=config.DEFAULT_PWD_KEY_LENGTH,
        iterations=config.DEFAULT_PWD_ITERATIONS,
    ):
        """Password init
        Args:
            hash_algorithm(HashAlgorithm): An instance of Hash algorithm.
            Defaults to the DEFAULT_HASH_ALG value set in the config.py file.
            salt_length (int) – The number of bytes of the salt. Secure values are 16 (128-bits)
            or longer and randomly generated. Defaults to the DEFAULT_PWD_SALT_LENGTH value set
            in the config.py file.
            length (int) – The desired length of the derived key in bytes.
            Maximum is (232 - 1) * algorithm.digest_size.
            Defaults to the DEFAULT_PWD_KEY_LENGTH value set in the config.py file.
            iterations (int) – The number of iterations to perform of the hash function.
            This can be used to control the length of time the operation takes.
            Higher numbers help mitigate brute force attacks against derived keys.
            Defaults to the DEFAULT_PWD_ITERATIONS value set in the config.py file.
        """
        self.hash_algorithm = hash_algorithm
        self.salt_length = salt_length
        self.length = length
        self.iterations = iterations

    def gen_salt(self, length=16):
        """Generate a salt_

        Args:
            length (int, optional): Length of the salt. Defaults to 16.

        Returns:
            bytes: salt
        """
        return os.urandom(int(length))

    def derive(self, password):
        """Generate a password using the PDKDF2 algorithm

        Args:
            password(bytes or str) : the password. Bytes or string.
            If string, encoded in UTF-8.

        Returns:
            bytes: The derived key
            bytes: The salt
        """
        # generate the salt
        salt = self.gen_salt(self.salt_length)
        # prepare the cipher
        kdf = PBKDF2HMAC(
            algorithm=utils.hash_algorithm(self.hash_algorithm),
            length=self.length,
            salt=salt,
            iterations=self.iterations,
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
            attempt(bytes or str) : the tentative password to be checked. Bytes or string.
            If string, encoded in UTF-8.
            key(bytes): The key
            salt(bytes): The salt

        Returns:
            bool: True if verified, False if not verified

        """
        # prepare the cipher
        kdf = PBKDF2HMAC(
            algorithm=utils.hash_algorithm(self.hash_algorithm),
            length=self.length,
            salt=salt,
            iterations=self.iterations,
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
