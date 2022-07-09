# -*- coding: utf-8 -*-
"""sshkeypair.py - generate, save and load keypairs for OpenSSH

Class:
- SSH
"""
import base64
import binascii
import os

from cryptography.hazmat.primitives import hashes

from . import files
from . import utils
from .config import Base
from .config import SSHKeyPairConfig
from .privatekey import PrivateKey
from .publickey import PublicKey


class SSHKeyPair(Base):
    """SSH Object - extends Base"""

    def __init__(self, **kwargs):
        """SSHKeyPair class constructor

        Args:
            config (SSHKeyPairConfig, optional): The configuration.
            private_key (PrivateKey, optional): The private key.
                An instance of PrivateKey.
            public_key (PublicKey, optional): The public key. An instance of PublicKey.
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and
                DSA (legacy) are supported.
                Defaults to `RSA`.

        """
        super().__init__(**kwargs)
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop("config", SSHKeyPairConfig())
        # private_key object
        if not hasattr(self, "private_key"):
            self._private_key = kwargs.pop("private_key", PrivateKey())
        # public_key object
        if not hasattr(self, "public_key"):
            self._public_key = kwargs.pop("public_key", PublicKey())
        # alg object
        if not hasattr(self, "alg"):
            self._alg = kwargs.pop("alg", "RSA").upper()

    @property
    def public_key(self):
        """Get the public_key attribute

        Returns:
            PublicKey: An instance of PublicKey.

        """
        return self._public_key

    @public_key.setter
    def public_key(self, key):
        """Set the key with a pre-existing Public Key

        Args:
            key (PublicKey): An instance of PublicKey.

        """
        self._public_key = key

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

    # Private Key
    def gen_private_key(
        self,
        alg="RSA",
        key_size=None,
        public_exponent=None,
        curve=None,
    ):
        """Generate a private key for OpenSSH

        Args:
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and
                DSA (legacy) are supported.
                Defaults to `RSA`.
            key_size (int, optional): Key size. Used in RSA.
                Defaults to None.
            public_exponent (int, optional): Public Exponent. Used in RSA.
                Defaults to None.
            curve (str, optional): The name of the elliptic curve for ECDSA.
                Defaults to None.
            passphrase (str, optional): The passphrase.
                Defaults to None.

        """
        # handle the algorithm
        if self._alg is None:
            alg = alg.upper()  # Correct some input mistakes
            if alg in ["RSA", "ED25519", "DSA", "EC", "ECDSA"]:
                self._alg = alg
            else:
                raise Exception("SSH algorithm not supported by cryptopyutils")
        # ECDSA
        if self._alg == "ECDSA":
            self._alg = "EC"
        # DSA
        if self._alg == "DSA":
            key_size = self._config.dsa_key_size

        # Generate the private key
        self._private_key.gen(self._alg, key_size, public_exponent, curve)

    def save_private_key(
        self,
        path,
        passphrase=None,
        file_mode=None,
        force=False,
    ):
        """Save the SSH private key

        Args:
            path (str): The file path where the private key will be saved.
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
        # Note: SSH format requires PEM encoding.
        return self._private_key.save(
            path,
            "PEM",
            "OpenSSH",
            passphrase,
            file_mode,
            force,
        )

    def load_private_key(self, path, passphrase=None):
        """Load a SSH Private Key

        Args:
            filepath(str): The file path of the private key to be loaded.
            passphrase (str, optional): The passphrase.
                Default to None.

        """
        self._private_key.load(path, "OpenSSH", passphrase)

    # Public Key
    def gen_public_key(self):
        """Generate the SSH public key

        Assumes you have generated the private key first.

        """
        if self._alg in ["RSA", "ED25519", "DSA", "EC"]:
            self._public_key.gen(self._alg, self.private_key)
        else:
            raise Exception("SSH algorithm not supported by cryptopyutils")

    def load_public_key(self, path):
        """Load a SSH Public Key

        Args:
            path(str): The file path of the public key to be loaded.

        """
        data = files.read(path)
        self.public_key.load(path, "OpenSSH")

    def save_public_key(
        self,
        path,
        file_mode=None,
        force=False,
        comment=None,
    ):
        """Save the SSH public key

            Will open the file after saving it to apprend the comment if provided.

        Args:
            path (str): The file path where the public key will be saved.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.
            comment (str, optional): comment. Typically user@host format to be appended
                at the end of the public key.
                Defaults to None.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        status = self.public_key.save(path, "OpenSSH", "OpenSSH", file_mode, force)
        # return False if public key not saved
        if status is False:
            return False
        # if comment is set then open the file and append it
        if comment != None:
            # read the file
            data = files.read(path, istext=True)
            # modify the content
            data = "%s %s" % (data, comment)
            # write the file back
            files.write(path, data, istext=True)
        # return the filepath
        return True

    def hash_fingerprint(self, path, hash_alg=None):
        """Get the fingerprint based on a hash function

        equivalent to ssh-keygen -l -f /id_rsa.pub | awk '(print $2)'

        Args:
            path (str): path to the public key file
            hash_alg (str, optional): The hash algorithm.
                Defaults to None.

        """
        # Defaults
        if hash_alg is None:
            hash_alg = self.config.hash_alg
        # Read the public key
        data_public_key1 = files.read(path, istext=True)
        # Pick the hash algorithm
        digest = hashes.Hash(utils.hash_algorithm(alg=hash_alg))
        # obtain the bytes of the public key
        pubk_bytes = binascii.a2b_base64(data_public_key1.split(" ")[1])
        # compute the fingerprint, encode it to base 64, remove equal signs and add the hash alg
        digest.update(pubk_bytes)
        fingerp = base64.b64encode(digest.finalize()).decode()
        fingerp = fingerp.replace("=", "")
        # remove the dash  in the hash algorithm
        hash = str(hash_alg).replace("-", "")
        # return the fingerpring
        return hash + ":" + fingerp

    # Key pair

    def key_pair(
        self,
        alg="RSA",
        out_dir=None,
        passphrase=None,
        file_mode=None,
        force=False,
        key_size=None,
        public_exponent=None,
        curve_length=521,
        comment=None,
        is_user=True,
    ):
        """Generate the SSH key pair using RSA

        Args:
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and DSA
                (legacy) are supported. Defaults to `RSA`.
            out_dir (str, optional): The output directory path.
                Defaults to None.
            passphrase (str, optional): The passphrase.
                Defaults to None.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.
            key_size (int, optional): Key size. Used in RSA.
                Defaults to None.
            public_exponent (int, optional): Public Exponent. Used in RSA.
                Defaults to None.
            curve (int): The elliptic curve length for ECDSA. Can be 256, 384 or 521.
                Defaults to 521.
            comment (str, optional): comment. Typically user@host format to be appended
                at the end of the public key.
                Defaults to None.
            is_user (bool, optional): Is the key a user key (True) or a system key
                (False).
                Defaults to True.

        Returns:
            [bool, bool], [str, str]: The first is the private key, the second is the public key.
                bool: True if successful. False if already exists and not forced
                to overwrite.
                str: Private key and public key file pathes

        """
        # algorithm supported
        if alg not in ["RSA", "ED25519", "ECDSA", "DSA"]:
            raise Exception("SSH algorithm not supported by cryptopyutils")
        else:
            self._alg = alg
        # output directory
        if out_dir is None:
            if is_user:
                out_dir = self._config.user_dir
            else:
                out_dir = self._config.system_dir

        # private key files
        # case of elliptic curves
        if self._alg == "RSA":
            pkfp = os.path.join(out_dir, "id_rsa")
            # generate and save the private key
            self.gen_private_key("RSA", key_size, public_exponent)
        elif self._alg == "ED25519":
            pkfp = os.path.join(out_dir, "id_ed25519")
            self.gen_private_key("ED25519")
        elif self._alg == "ECDSA":
            # Choose the proper elliptic curve
            curves = {
                "256": "SECP256R1",
                "384": "SECP384R1",
                "521": "SECP521R1",
            }
            if str(curve_length) in curves.keys():
                curve = curves[str(curve_length)]
            else:
                raise Exception("ECDSA curve not supported by cryptopyutils")
            pkfp = os.path.join(out_dir, "id_ecdsa")
            self.gen_private_key("EC", curve=curve)
        elif self._alg == "DSA":
            pkfp = os.path.join(out_dir, "id_dsa")
            self.gen_private_key("DSA")
        else:
            # Not supported
            return [None, None], [None, None]
        # save the private key
        status = self.save_private_key(pkfp, passphrase, file_mode, force)
        # return False if private key not saved
        if status is False:
            return [False, None], [pkfp, None]
        # generate the public key
        self.gen_public_key()
        # generate public key filepath
        pubkfp = pkfp + ".pub"
        # save the public key
        status_pub = self.save_public_key(pubkfp, file_mode, force, comment)
        # return False if public key not saved
        if status_pub is False:
            return [True, False], [pkfp, pubkfp]
        # else return
        return [True, True], [pkfp, pubkfp]
