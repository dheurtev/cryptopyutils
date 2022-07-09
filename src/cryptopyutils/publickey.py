# -*- coding: utf-8 -*-
"""publickey.py - Public Key : generate, save, load, encrypt, verify

Class:

* PublicKey

"""
import base64

from cryptography.exceptions import InvalidSignature
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
from .config import PublicKeyConfig


class PublicKey(Base):
    """Public Key Class - extends Base

    Usage:

    * initialize : pubk = PublicKey(PublicKey()) or pk = PublicKey()
                or pubk = PublicKey(private_key=PrivateKey())
    * generate the key: pubk.gen()
    * save key: pubk.save(filepath)
    * load key: pubk.load(filepath)
    * decrypt: pubk.decrypt(ciphertext)
    * verify: pubk.verify(signature, message)

    """

    def __init__(self, **kwargs):
        """PublicKey class initiator

        Args:
            config (PublicKeyConfig, optional): The configuration.
            key (Cryptography PublicKey, optional) : The public key.
                An instance of Cryptography PublicKey.
                Defaults to None.
            private_key (PrivateKey, optional): The private key.
                An instance of PrivateKey.
                Defaults to None.

        """
        super().__init__(**kwargs)
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop("config", PublicKeyConfig())
        # key object (cryptography compatible)
        if not hasattr(self, "key"):
            self._key = kwargs.pop("key", None)
        # private_key object
        if not hasattr(self, "private_key"):
            self._private_key = kwargs.pop("private_key", None)

    # Generate
    def gen(self, alg=None, private_key=None):
        """Generate the Public Key

        Args:
            alg (str): The key algorithm. RSA, EC, ED448, ED25519 and DSA
                are supported.
                Defaults to None.
            private_key (PrivateKey, optional): The private key.
                An instance of PrivateKey.
                Defaults to None.
        """
        # Defaults
        if alg is None:
            alg = self._config.alg.upper()
        if private_key is not None:
            self._private_key = private_key

        # Generate the public key based on the algorithm
        if alg == "RSA":
            self._key = self.private_key.key.public_key()
        elif alg == "DSA":
            self._key = self.private_key.key.public_key()
        elif alg == "ED448":
            self._key = self.private_key.key.public_key()
        elif alg == "ED25519":
            self._key = self.private_key.key.public_key()
        elif alg == "EC":
            self._key = self.private_key.key.public_key()
        else:
            # Not implemented - Tries to read public_key()
            self._key = self.private_key.key.public_key()

    # Load
    def load(
        self,
        path,
        encoding=None,
    ):
        """Load the public key

        Args:
            path(str): The file path of the public key to be loaded.
            encoding (str, optional): Encoding PEM, DER, openSSH, X962, SMIME.
                Defaults to None.

        """
        # Default encoding
        if encoding is None:
            encoding = self._config.encoding

        # serialize based on encoding
        if encoding == "PEM":
            lines = files.read(path)
            self._key = serialization.load_pem_public_key(lines)
        elif encoding == "DER":
            lines = files.read(path)
            self._key = serialization.load_der_public_key(lines)
        elif encoding == "OpenSSH":
            lines = files.read(path)
            self._key = serialization.load_ssh_public_key(lines)
        elif encoding == "X962":
            self._key = files.read(path)
        elif encoding == "SMIME":
            self._key = files.read(path, istext=True)
        else:
            self._key = files.read(path)

    def load_pem(self, path):
        """Load a PEM Public Key

        Args:
            path(str): The file path of the public key to be loaded.

        """
        self.load(path, "PEM")

    def load_der(self, path):
        """Load a DER Public Key

        Args:
            path(str): The file path of the public key to be loaded.

        """
        self.load(path, "DER")

    # Encode
    def _encode(
        self,
        encoding=None,
        file_format=None,
    ):
        """Encode the public key to a given format

        Notes:

        * SSH format requires PEM encoding.
        * Default SubjectPublicKeyInfo format (None) requires PEM or DER encoding
        * PKCS8 is the default (Traditional openSSL style is kept as legacy)

        Args:
            encoding (str, optional): Encoding PEM, DER or OpenSSH.
                Defaults to None.
            file_format (str, optional): Format : SubjectPublicKeyInfo, PKCS1
                or OpenSSH.
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
        data = self._key.public_bytes(
            encoding=utils.file_encoding(encoding),
            format=utils.public_format(file_format),
        )
        return data

    # Save
    def save(
        self,
        path,
        encoding=None,
        file_format=None,
        file_mode=None,
        force=False,
    ):
        """Save the public key to file

        Notes:

        * SSH format requires PEM encoding.
        * Default SubjectPublicKeyInfo format (None) requires PEM or DER encoding
        * PKCS8 is the default (Traditional openSSL style is kept as legacy)

        Args:
            path (str): The file path where the public key will be saved.
            encoding (str, optional): Encoding PEM, DER or OpenSSH.
               Defaults to None.
            file_format (str, optional): Format : SubjectPublicKeyInfo, PKCS1
                or OpenSSH.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        # encoding
        data = self._encode(encoding, file_format)

        # early return no overwriting if exists and not forced
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
        file_mode=None,
        force=False,
    ):
        """Save a PEM private key

        Args:
            path (str): The file path where the private key will be saved.
            file_format (str, optional): Format : SubjectPublicKeyInfo, PKCS1
                or OpenSSH.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, "PEM", file_format, file_mode, force)

    def save_der(
        self,
        path,
        file_format=None,
        file_mode=None,
        force=False,
    ):
        """Save a DER private key

        Args:
            path (str): The file path where the private key will be saved.
            file_format (str, optional): Format : SubjectPublicKeyInfo, PKCS1
                or OpenSSH.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, "DER", file_format, file_mode, force)

    @property
    def key(self):
        """Get the key attribute

        Returns:
            Cryptography Public Key: An instance of PublicKey from Cryptography.
        """
        return self._key

    @key.setter
    def key(self, key):
        """Set the key with a pre-existing Cryptography Public Key

        Args:
            key (Cryptography Public Key): An instance of PublicKey from Cryptography.

        """
        self._key = key

    @property
    def private_key(self):
        """Get the private_key attribute

        Returns:
           PrivateKey : An instance of PrivateKey.

        """
        return self._private_key

    @private_key.setter
    def private_key(self, key):
        """Set the key with a pre-existing private key

        Args:
            key (PrivateKey): An instance of PrivateKey.

        """
        self._private_key = key

    @property
    def keytext(self):
        """Returns the key in PEM SubjectPublicKeyInfo format

        Returns:
            str: the key.

        """
        encoded = self._encode("PEM", "SubjectPublicKeyInfo")
        return encoded.decode("UTF-8")

    # Encrypt
    def encrypt(self, plaintext, padding=None):
        """Encrypt the message using the public key

        The plaintext can be binary or text format.
        If text, it is encoded in UTF-8.

        Args:
            plaintext(bytes or str): The plaintext to encrypt.
            padding(AsymmetricPadding, optional): An instance of AsymmetricPadding.
                Defaults to None.

        Returns:
            base64: The encrypted message in base 64 format.

        """
        # Defaults
        if padding is None:
            padding = utils.oaep_mgf1_padding(self._config.hash_alg)
        else:
            padding = None
        # Input as bytes or str
        if isinstance(plaintext, str):
            msg = plaintext.encode("utf-8")
        else:
            msg = plaintext
        # generate and return the encrypted text in base 64 format
        return base64.b64encode(self._key.encrypt(msg, padding))

    # Verify
    def verify(
        self,
        signature,
        message,
        hash_alg=None,
        padding=None,
        pre_hashed=False,
    ):
        """Sign the message using the public key

        The message to verify can be binary or text format.
        If text, it is encoded in UTF-8.

        Supports RSA, DSA, ED448, ED25519, Elliptic Curve (with ECDSA) Private Keys.

        Args:
            signature (base64): The signature in base64 format.
            message (bytes or str): The message to verify.
            hash_alg (str, optional) – the hash algorithm.
                Defaults to None.
            padding (AsymmetricPadding, optional): An instance of AsymmetricPadding.
                Not in DSA.
                Defaults to None.
            pre_hashed (bool, optional): Flag indicating the the message is a digest
                from pre-hashed values (message too large).
                Defaults to False.

        Raises:
            bool: False if the signature does not validate, else True.

        """
        # Defaults
        if hash_alg is None:
            hash_alg = self._config.hash_alg
        if padding is None:
            padding = utils.pss_mgf1_padding(hash_alg)
        # Decode the signature from base64 format
        sig = base64.b64decode(signature)
        verif = None
        try:
            # handles both str and bytes
            if isinstance(message, str):
                msg = message.encode("utf-8")
            else:
                msg = message
            # pick the correct algorithm
            if pre_hashed:
                alg = asymutils.Prehashed(utils.hash_algorithm(hash_alg))
            else:
                alg = utils.hash_algorithm(hash_alg)

            if isinstance(self.key, rsa.RSAPublicKey):
                self._key.verify(sig, msg, padding, alg)
            elif isinstance(self.key, dsa.DSAPublicKey):
                self._key.verify(sig, msg, alg)
            elif isinstance(self.key, ed448.Ed448PublicKey):
                self._key.verify(sig, msg)
            elif isinstance(self.key, ed25519.Ed25519PublicKey):
                self._key.verify(sig, msg)
            elif isinstance(self.key, ec.EllipticCurvePublicKey):
                self._key.verify(sig, msg, ec.ECDSA(alg))
            else:
                # NOTIMPLEMENTED
                return None
            verif = True
        except InvalidSignature:
            verif = False
        return verif
