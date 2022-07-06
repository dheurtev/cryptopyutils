# -*- coding: utf-8 -*-
"""key.py - Key
"""
import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import rsa

from . import files
from . import utils
from .config import Base
from .config import PrivateKeyConfig


class Key(Base):
    """Key class - extends Base"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # type of key: private or public
        if not hasattr(self, "keytype"):
            self._keytype = kwargs.pop("keytype", "private")
        # name of the key - typically the host
        if not hasattr(self, "name"):
            self._name = kwargs.pop("name", None)
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop("config", PrivateKeyConfig())
        # algorithm
        if not hasattr(self, "alg"):
            self._key = kwargs.pop("alg", None)
        # key object (cryptography compatible)
        if not hasattr(self, "key"):
            self._key = kwargs.pop("key", None)
        # key represented in base64
        if not hasattr(self, "keyb64"):
            self._keyb64 = kwargs.pop("keyb64", None)
        # key represented in bytes
        if not hasattr(self, "keybytes"):
            self._keybytes = kwargs.pop("keybytes", None)
        # key file path
        if not hasattr(self, "filepath"):
            self._filepath = kwargs.pop("filepath", None)
        # key encoding
        if not hasattr(self, "encoding"):
            self._encoding = kwargs.pop("encoding", None)
        # key formatting
        if not hasattr(self, "formatting"):
            self._formatting = kwargs.pop("formatting", None)
        # key padding
        if not hasattr(self, "padding"):
            self._padding = kwargs.pop("padding", None)
        # file mode
        self._file_mode = None
        # file ext
        self._file_ext = None

    def gen(self):
        # case private key
        # case public key

        pass

    def _gen_private_key(
        self,
        alg,
        key_size=None,
        public_exponent=None,
        curve=None,
    ):
        """Generate the private key based on the keytype

        Args:
            alg (str): The key algorithm.
            key_size (int, optional): Key size.
            Defaults to the DEFAULT_RSA_KEY_SIZE value set in the config.py file.
            Used in DSA and RSA.
            public_exponent (int, optional): Public Exponent.
            Defaults to the DEFAULT_RSA_PUBLIC_EXPONENT value set in the config.py file.
            Used in RSA.
            curve (str): The name of the elliptic curve
            Defaults to the DEFAULT_ELLIPTIC_CURVE value set in the config.py file.

        Returns:
            obj: The private key. An instance of object (RSAPrivateKey or DSAPrivateKey or
            Ed448PrivateKey or Ed25519PrivateKey or EllipticCurvePrivateKey).
        """
        self._alg = alg

        if self._alg == "rsa" and key_size is None:
            key_size = self.config.key_size

        if public_exponent is None:
            self._public_exponent = public_exponent
        if curve is not None:
            self._curve = curve

        if self.alg == "RSA":
            self.gen_rsa(rsa_key_size, public_exponent)
        elif self.alg == "DSA":
            self.gen_dsa(dsa_key_size)
        elif self.alg == "ED448":
            self.gen_ed448()
        elif self.alg == "ED25519":
            elf.gen_ed25519()
        elif self.alg == "EC":
            self.gen_ec(curve)
        else:
            # Not implemented - use RSA
            return None

    def load(self, path=None, encoding=None, passphrase=None):
        """Load the private key or the public key

        Args:
            path(str, optional): The file path of the key to be loaded.
            Defaults to None.
            encoding (str, optional): Encoding PEM, DER, OpenSSH, RAW, X962, SMIME.
            Defaults to None.
            passphrase (str, optional): The passphrase. Only for encrypted PEM, DER or openSSH files.
            Default to None.
        """
        # record the file path
        if path is not None:
            self._file_path = path
            # record the file name
            self._name = path.split("/")[-1]
            # record the file extention
            self._file_ext = os.path.splitext(path)
        # record the file mode
        self._file_mode = files.get_chmod(self.file_path)
        # passphrase
        if passphrase is not None:
            pwd = utils.convert_passphrase(passphrase)
        else:
            pwd = None
        # encoding
        if encoding is not None:
            self._encoding = encoding

        if self._encoding == "PEM":
            lines = files.read(self.path)
            self._key = serialization.load_pem_private_key(lines, pwd)
        elif self._encoding == "DER":
            lines = files.read(self.path)
            self._key = serialization.load_der_private_key(lines, pwd)
        elif self._encoding == "OpenSSH":
            lines = files.read(self.path)
            self._key = serialization.load_ssh_private_key(lines, pwd)
        elif self._encoding == "RAW":
            self._key = files.read(self.path)
        elif self._encoding == "X962":
            self._key = files.read(self.path)
        elif self._encoding == "SMIME":
            self._key = files.read(self.path, istext=True)
        else:
            self._key = files.read(self.path)

    def _convert(self):
        # TODO
        pass

    def save(self, encoding=None, fmt=None):
        pass

    @property
    def name(self):
        return self._name

    @property
    def key(self):
        return self._key

    @property
    def filepath(self):
        return self._filepath

    @property
    def keyb64(self):
        return self.keyb64

    @property
    def keybytes(self):
        return self.keybytes

    @property
    def pem(self):
        pass

    @property
    def der(self):
        pass

    @property
    def raw(self):
        pass

    @property
    def openssh(self):
        pass

    @property
    def X962(self):
        pass

    @property
    def SMIME(self):
        pass


class PrivateKey(Key):
    """PrivateKey Object - Extends Key"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._key_type = "private"
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop("config", PrivateKeyConfig())
