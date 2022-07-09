# -*- coding: utf-8 -*-
"""privatekey.py - Private Key : generate, save, load, decrypt, sign

Class:

* PrivateKey

"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils as asymutils

from . import files
from . import utils
from .config import Base
from .config import PrivateKeyConfig


class PrivateKey(Base):
    """PrivateKey class - extends Base

    Usage (minimum requirements):

    * initialize : privk = PrivateKey() or privk = PrivateKey(PrivateKey())
    * generate key: privk.gen(alg)
    * save key: privk.save(filepath)
    * load key: privk.load(filepath)
    * decrypt: privk.decrypt(ciphertext)
    * sign: privk.sign(message)

    """

    def __init__(self, **kwargs):
        """PrivateKey class initiator

        Args:
            config (PrivateKeyConfig, optional): The configuration.
            key (PrivateKey, optional): The private key. An instance of RSAPrivateKey.
                or other cryptography private key object.

        """
        super().__init__(**kwargs)
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop("config", PrivateKeyConfig())
        # key object (cryptography compatible)
        if not hasattr(self, "key"):
            self._key = kwargs.pop("key", None)

    # Generate
    def gen(
        self,
        alg=None,
        key_size=None,
        public_exponent=None,
        curve=None,
    ):
        """Generate the private key

        Args:
            alg (str): The key algorithm. RSA, EC, ED448, ED25519 and DSA are supported.
                Defaults to None.
            key_size (int, optional): Key size. Used in DSA and RSA.
                Defaults to None.
            public_exponent (int, optional): Public Exponent. Used in RSA.
                Defaults to None.
            curve (str): The name of the elliptic curve.
                Defaults to None.

        """
        # Defaults
        if alg is None:
            alg = self._config.alg.upper()
        # Generate based on the algorithm
        if alg == "RSA":
            self.gen_rsa(key_size, public_exponent)
        elif alg == "DSA":
            self.gen_dsa(key_size)
        elif alg == "ED448":
            self.gen_ed448()
        elif alg == "ED25519":
            self.gen_ed25519()
        elif alg == "EC":
            self.gen_ec(curve)
        else:
            # Not implemented - use RSA
            pass

    def gen_rsa(
        self,
        key_size=None,
        public_exponent=None,
    ):
        """Generate a RSA private key

        Args:
            key_size (int, optional): Key size.
                Defaults to None.
            public_exponent (int, optional): Public Exponent.
                Defaults to None.
        """
        # Default config
        if key_size is None:
            key_size = self._config.rsa_key_size
        if public_exponent is None:
            public_exponent = self._config.rsa_public_exponent
        # Generate the key
        self._key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
        )

    def gen_dsa(self, key_size=None):
        """Generate a DSA private key

        Args:
            key_size (int, optional): Key size.
                Defaults to None.

        """
        # Default config
        if key_size is None:
            key_size = self._config.dsa_key_size
        # Generate the key
        self._key = dsa.generate_private_key(
            key_size=key_size,
        )

    def gen_ed448(self):
        """Generate an ED448 private key"""
        # Generate the key
        self._key = ed448.Ed448PrivateKey.generate()

    def gen_ed25519(self):
        """Generate an ED25519 private key"""
        # Generate the key
        self._key = ed25519.Ed25519PrivateKey.generate()

    def gen_ec(self, curve=None):
        """Generate an Elliptic Curve private key

        Args:
            curve (str): The name of the elliptic curve.
                Defaults to None.

        """
        # Default config
        if curve is None:
            curve = self._config.elliptic_curve
        # Generate the key
        self._key = ec.generate_private_key(utils.ellipctic_curve(curve))

    # Load

    def load(self, path, encoding=None, passphrase=None):
        """Load the private key

        Args:
            path(str): The file path of the key to be loaded.
                Defaults to None.
            encoding (str, optional): Encoding PEM, DER or OpenSSH.
                Defaults to None.
            passphrase (str, optional): The passphrase. Only for encrypted PEM or
                openSSH files.
                Default to None.
        """
        # passphrase
        if passphrase is not None:
            pwd = utils.convert_passphrase(passphrase)
        else:
            pwd = None
        # encoding
        if encoding is None:
            encoding = self._config.encoding

        if encoding == "PEM":
            lines = files.read(path)
            self._key = serialization.load_pem_private_key(lines, pwd)
        elif encoding == "DER":
            lines = files.read(path)
            self._key = serialization.load_der_private_key(lines, pwd)
        elif encoding == "OpenSSH":
            lines = files.read(path)
            self._key = serialization.load_ssh_private_key(lines, pwd)
        else:
            self._key = files.read(path)

    def load_pem(self, path, passphrase=None):
        """Load a PEM Private Key

        Args:
            path(str): The file path of the private key to be loaded.
            passphrase (str, optional): The passphrase.
                Defaults to None.
        """
        self.load(path, "PEM", passphrase)

    def load_der(self, path, passphrase=None):
        """Load a DER Private Key

        Args:
            path(str): The file path of the private key to be loaded.
            passphrase (str, optional): The passphrase.

        """
        self.load(path, "DER", passphrase)

    # Encode
    def _encode(
        self,
        encoding=None,
        file_format=None,
        passphrase=None,
    ):
        """Encode the private key to a given format
        Notes:

        * SSH format requires PEM encoding.
        * PKCS8 is the default (Traditional openSSL style is kept as legacy)

        Args:
            encoding (str, optional): Encoding PEM, DER or OpenSSH.
                Defaults to None.
            file_format (str, optional): Format : PKCS8, PKCS1 or OpenSSH.
                Defaults to None.
            passphrase (str, optional): The passphrase. Only for PEM.
                Defaults to None.

        Returns:
            bytes: The encoded and formatted key.

        """
        # Defaults
        if encoding is None:
            encoding = self._config.encoding

        if file_format is None:
            file_format = self._config.file_format

        # Encode
        data = self._key.private_bytes(
            encoding=utils.file_encoding(encoding),
            format=utils.private_format(file_format),
            encryption_algorithm=utils.private_alg(passphrase),
        )
        return data

    # Save
    def save(
        self,
        path,
        encoding=None,
        file_format=None,
        passphrase=None,
        file_mode=None,
        force=False,
    ):
        """Save the private key

        Args:
            path (str): The file path where the private key will be saved.
            encoding (str, optional): Encoding PEM, DER or OpenSSH.
            Defaults to None.
            file_format (str, optional): Format : PKCS8, PKCS or OpenSSH.
            Defaults to None.
            passphrase (str, optional): The passphrase.
            Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
            Defaults to None.
            force (bool, optional): Force to replace file if already exists.
            Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        # encode
        data = self._encode(encoding, file_format, passphrase)
        # early return no overwriting if exists and not force
        if files.file_exists(path) and (not force):
            return False
        # write the key content
        if encoding in ["OpenSSH"]:
            files.write(path, data, istext=True)
        else:
            files.write(path, data)
        # set the chmod
        if file_mode is not None:
            files.set_chmod(path, file_mode)
        else:
            files.set_chmod(path, self._config.file_mode)

        # return the filepath
        return True

    def save_pem(
        self,
        path,
        file_format=None,
        passphrase=None,
        file_mode=None,
        force=False,
    ):
        """Save a PEM private key

        Args:
            path (str): The file path where the private key will be saved.
            file_format (str, optional): Format : PKCS8, PKCS1 or OpenSSH.
                Defaults to None.
            passphrase (str, optional): The passphrase.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, "PEM", file_format, passphrase, file_mode, force)

    def save_der(
        self,
        path,
        file_format=None,
        passphrase=None,
        file_mode=None,
        force=False,
    ):
        """Save a DER private key

        Args:
            path (str): The file path where the private key will be saved.
            file_format (str, optional): Format : PKCS8, PKCS1 or OpenSSH.
                Defaults to None.
            passphrase (str, optional): The passphrase.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, "DER", file_format, passphrase, file_mode, force)

    @property
    def key(self):
        """Get the key attribute

        Returns:
            Cryptography Private Key: An instance of an alg PrivateKey from Cryptography
                (e.g. RSAPrivateKey).

        """
        return self._key

    @key.setter
    def key(self, key):
        """Set the key with a pre-existing Cryptography Private Key

        Args:
            key (Cryptography Private Key): An instance of an alg PrivateKey
                from Cryptography.

        """
        self._key = key

    @property
    def keytext(self):
        """Returns the key in PEM PKCS8 format

        Returns:
            str: the key.

        """
        encoded = self._encode("PEM", "PKCS8")
        return encoded.decode("UTF-8")

    # Decryption
    def decrypt(
        self,
        ciphertext,
        padding=None,
        text=False,
    ):
        """Decrypt the encrypted message using the private key

        The decrypted message can be represented in binary or text format.
        If text, it is decoded to UTF-8.

        Args:
            ciphertext (base64): The ciphertext to decrypt in base 64.
            padding (AsymmetricPadding, optional): An instance of AsymmetricPadding.
                Defaults to None.
            text (bool, optional): Flag indicating if the output should be treated
            as text.
                Defaults to False.

        Returns:
            bytes or str: The plaintext.

        """
        # Defaults
        if padding is None:
            padding = utils.oaep_mgf1_padding(self._config.hash_alg)
        # Decode from Base64 input
        bdecoded = base64.b64decode(ciphertext)
        # Decrypt
        decrypted = self.key.decrypt(bdecoded, padding)
        # Return str or bytes
        if text:
            return decrypted.decode("utf-8")
        else:
            return decrypted

    # signature
    def sign(
        self,
        message,
        hash_alg=None,
        padding=None,
        pre_hashed=False,
    ):
        """Sign the message using the private key

        The message to sign is represented in binary or text format.
        If text, it is encoded in UTF-8.

        Supports RSA, DSA, ED448, ED25519, Elliptic Curve (with ECDSA) Private Keys.

        Args:
            message (bytes or str): The message to sign.
            hash_alg (str) – the hash algorithm.
                Defaults to None.
            padding (AsymmetricPadding, optional): An instance of AsymmetricPadding.
                Not in DSA.
                Defaults to None.
            pre_hashed (bool, optional): Flag indicating the the message is a digest
                from pre-hashed values (message too large).
                Defaults to False

        Returns:
            str: The signature in base64 format.

        """
        # Defaults
        if hash_alg is None:
            hash_alg = self._config.hash_alg
        if padding is None:
            padding = utils.pss_mgf1_padding(hash_alg)
        # Treat the message as str or bytes
        if isinstance(message, str):
            msg = message.encode("utf-8")
        else:
            msg = message
        # Obtain the hash algorithm
        if pre_hashed:
            alg = asymutils.Prehashed(utils.hash_algorithm(hash_alg))
        else:
            alg = utils.hash_algorithm(hash_alg)
        # Sign the message
        if isinstance(self.key, rsa.RSAPrivateKey):
            signature = self.key.sign(msg, padding, alg)
        elif isinstance(self.key, dsa.DSAPrivateKey):
            signature = self.key.sign(msg, alg)
        elif isinstance(self.key, ed448.Ed448PrivateKey):
            signature = self.key.sign(msg)
        elif isinstance(self.key, ed25519.Ed25519PrivateKey):
            signature = self.key.sign(msg)
        elif isinstance(self.key, ec.EllipticCurvePrivateKey):
            signature = self.key.sign(msg, ec.ECDSA(alg))
        else:
            # NOTIMPLEMENTED
            return None
        # Return a base 64 representation of the signature
        return base64.b64encode(signature)
