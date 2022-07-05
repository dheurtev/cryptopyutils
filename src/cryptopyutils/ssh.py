# -*- coding: utf-8 -*-
"""ssh.py - SSH : private key and public key generate, save, load for OpenSSH

Class:
- SSH

"""
# Copyright 2022 David HEURTEVENT <david@heurtevent.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import base64
import binascii
import os

from cryptography.hazmat.primitives import hashes

from ...cryptopyutils import config
from ...cryptopyutils import files
from ...cryptopyutils import utils
from .privatekey import PrivateKey
from .publickey import PublicKey

# Private key


class SSH:
    """SSH Object"""

    def __init__(
        self,
    ):
        """SSH Object init"""
        self.fingerprint = None
        self.private_key = PrivateKey()
        self.public_key = PublicKey()

    def gen_private_key(
        self,
        alg="RSA",
        key_size=config.DEFAULT_SSH_RSA_KEY_SIZE,
        public_exponent=config.DEFAULT_SSH_RSA_PUBLIC_EXPONENT,
        curve=config.DEFAULT_ELLIPTIC_CURVE,
    ):
        """Generate a RSA or ED25519 private key for OpenSSH

        Args:
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and DSA (legacy) are supported. Defaults to `RSA`.
            key_size (int, optional): Key size.
            Defaults to the DEFAULT_SSH_RSA_KEY_SIZE value set in the config.py file.
            Used in RSA.
            public_exponent (int, optional): Public Exponent.
            Defaults to the DEFAULT_SSH_RSA_PUBLIC_EXPONENT value set in the config.py file.
            Used in RSA.
            curve (str): The name of the elliptic curve for ECDSA.
            Defaults to the DEFAULT_ELLIPTIC_CURVE value set in the config.py file.
            passphrase (str, optional): The passphrase. Defaults to None.

        Returns:
            obj: The private key. An instance of object (RSAPrivateKey or Ed25519PrivateKey).
        """
        if alg in ["RSA", "ED25519", "DSA", "EC"]:
            return self.private_key.gen(alg, key_size, public_exponent, curve)
        else:
            raise Exception("SSH algorithm not supported by cryptopyutils")

    def save_private_key(
        self,
        path=None,
        passphrase=None,
        dir=config.DEFAULT_OUTPUT_DIRECTORY,
        mode=config.DEFAULT_SSH_PRIV_KEY_MODE,
        force=True,
    ):
        """Save the SSH private key

        Args:
            path (str, optional): The file path where the private key will be saved.
            Defaults to None (will generate a temporary file).
            passphrase (str, optional): The passphrase. Defaults to None.
            dir (str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_SSH_PRIV_KEY_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists.
            Defaults to True.

        Returns:
            bool: True if successful. False if already exists and not forced to overwrite.
            str: The filepath where the private key has been saved.
        """
        # Note: SSH format requires PEM encoding.
        return self.private_key.save(
            path,
            passphrase,
            dir,
            mode,
            "PEM",
            "OpenSSH",
            force,
        )

    def load_private_key(self, path, passphrase=None):
        """Load a SSH Private Key

        Args:
            filepath(str): The file path of the private key to be loaded.
            passphrase (str, optional): The passphrase. Default to None.

        Returns:
            RSAPrivateKey: The private key. An instance of RSAPrivateKey.
        """
        return self.private_key.load(path, passphrase, "OpenSSH")

    # Public Key
    def gen_public_key(self):
        """Generate the SSH public key

        Assumes you have generate the private key first

        Returns:
            RSAPublicKey: An RSA public key object corresponding to the values of the private key.
            An instance of RSAPublicKey.
        """
        self.public_key = PublicKey(private_key=self.private_key)
        return self.public_key.gen()

    def load_public_key(self, path):
        """Load a SSH Public Key

        Args:
            path(str): The file path of the public key to be loaded.

        Returns:
            RSAPublicKey: The RSA public key.
            An instance of RSAPublicKey.
        """
        data = files.read(path)
        print(data)
        return self.public_key.load(path, "OpenSSH")

    def save_public_key(
        self,
        path=None,
        dir=config.DEFAULT_SSH_USER_DIR,
        mode=config.DEFAULT_SSH_PUB_KEY_MODE,
        force=True,
        comment=None,
    ):
        """Save the SSH public key

            Will open the file after saving it to apprend the comment if provided.

        Args:
            path (str, optional): The file path where the private key will be saved.
            Defaults to the DEFAULT_SSH_USER_DIR value set in the config.py file.
            dir (str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_SSH_PUB_KEY_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists. Defaults to True.
            comment (str, optional): comment. Typically user@host format to be appended at the end of the public key

        Returns:
            bool: True if successful. False if already exists and not forced to overwrite.
            str: The filepath where the public key has been saved.
        """
        status, fp = self.public_key.save(path, dir, mode, "OpenSSH", "OpenSSH", force)
        # return False if public key not saved
        if status is False:
            return False, fp
        # if comment is set then open the file and append it
        if comment != None:
            # read the file
            data = files.read(fp, istext=True)
            # modify the content
            data = "%s %s" % (data, comment)
            # write the file back
            files.write(fp, data, istext=True)
        # return the filepath
        return True, fp

    def hash_fingerprint(self, path, hash_algorithm=config.DEFAULT_HASH_ALG):
        """Get the fingerprint based on a hash function

        equivalent to ssh-keygen -l -f /id_rsa.pub | awk '(print $2)'

        Args:
            path (str): path to the public key file
            hash_algorithm (HashAlgorithm) – An instance of HashAlgorithm.
            Defaults to the DEFAULT_HASH_ALG value set in the config.py file.

        """
        data_public_key1 = files.read(path, istext=True)
        digest = hashes.Hash(utils.hash_algorithm(alg=hash_algorithm))
        pubk_bytes = binascii.a2b_base64(data_public_key1.split(" ")[1])
        # compute the fingerprint, encode it to base 64, remove equal signs and add the hash alg
        digest.update(pubk_bytes)
        fingerp = base64.b64encode(digest.finalize()).decode()
        fingerp = fingerp.replace("=", "")
        h = str(hash_algorithm).replace("-", "")
        return h + ":" + fingerp

    # Key pair
    def user_key_pair(
        self,
        alg="RSA",
        dir=config.DEFAULT_OUTPUT_DIRECTORY,
        passphrase=None,
        mode=config.DEFAULT_SSH_PRIV_KEY_MODE,
        force=True,
        key_size=config.DEFAULT_SSH_RSA_KEY_SIZE,
        public_exponent=config.DEFAULT_SSH_RSA_PUBLIC_EXPONENT,
        curve_length=521,
        comment=None,
    ):
        """Generate the SSH key pair using RSA

        Args:
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and DSA (legacy) are supported. Defaults to `RSA`.
            dir (str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            passphrase (str, optional): The passphrase. Defaults to None.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_SSH_PUB_KEY_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists. Defaults to True.
            key_size (int, optional): Key size.
            Defaults to the DEFAULT_SSH_RSA_KEY_SIZE value set in the config.py file.
            Used in RSA.
            public_exponent (int, optional): Public Exponent.
            Defaults to the DEFAULT_SSH_RSA_PUBLIC_EXPONENT value set in the config.py file.
            Used in RSA.
            curve (int): The elliptic curve length for ECDSA. Can be 256, 384 or 521.
            comment (str, optional): comment. Typically user@host format to be appended at the end of the public key

        Returns:
            [bool, bool]: True if successful. False if already exists and not forced to overwrite.
            [str, str]: The filepaths where the private key and the public key have been saved.
        """
        # algorithm supported
        if alg not in ["RSA", "ED25519", "ECDSA", "DSA"]:
            raise Exception("SSH algorithm not supported by cryptopyutils")

        # private key files
        # case of elliptic curves
        if alg == "RSA":
            pkfp = os.path.join(dir, "id_rsa")
            # generate and save the private key
            self.gen_private_key("RSA", key_size, public_exponent)
        elif alg == "ED25519":
            pkfp = os.path.join(dir, "id_ed25519")
            self.gen_private_key("ED25519")
        elif alg == "ECDSA":
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
            pkfp = os.path.join(dir, "id_ecdsa")
            self.gen_private_key("EC", curve=curve)
        elif alg == "DSA":
            pkfp = os.path.join(dir, "id_dsa")
            self.gen_private_key(
                "DSA",
                config.DEFAULT_SSH_DSA_KEY_SIZE,
                config.DEFAULT_SSH_RSA_PUBLIC_EXPONENT,
            )
        else:
            # Not supported
            return None
        # save the private key
        status, priv = self.save_private_key(pkfp, passphrase, None, mode, force)
        # return False if private key not saved
        if status is False:
            return [False, ""], [pkfp, ""]
        # generate the public key
        self.gen_public_key()
        # generate public key filepath
        pubkfp = pkfp + ".pub"
        # save the public key
        status, pub = self.save_public_key(pubkfp, None, mode, force, comment)
        # return False if public key not saved
        if status is False:
            return [True, False], [pkfp, ""]
        # else return
        return [True, True], [pkfp, pubkfp]

    def system_key_pair(
        self,
        alg="RSA",
        dir=config.DEFAULT_OUTPUT_DIRECTORY,
        passphrase=None,
        mode=config.DEFAULT_SSH_PRIV_KEY_MODE,
        force=True,
        key_size=config.DEFAULT_SSH_RSA_KEY_SIZE,
        public_exponent=config.DEFAULT_SSH_RSA_PUBLIC_EXPONENT,
        curve_length=521,
        comment=None,
    ):
        """Generate the SSH key pair using RSA

        Args:
            alg (str, optional): The key algorithm. RSA, ED25519, ECDSA and DSA (legacy) are supported. Defaults to `RSA`.
            dir (str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            passphrase (str, optional): The passphrase. Defaults to None.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_SSH_PUB_KEY_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists. Defaults to True.
            key_size (int, optional): Key size.
            Defaults to the DEFAULT_SSH_RSA_KEY_SIZE value set in the config.py file.
            Used in RSA.
            public_exponent (int, optional): Public Exponent.
            Defaults to the DEFAULT_SSH_RSA_PUBLIC_EXPONENT value set in the config.py file.
            Used in RSA.
            curve (int): The elliptic curve length for ECDSA. Can be 256, 384 or 521.
            comment (str, optional): comment. Typically user@host format to be appended at the end of the public key

        Returns:
            bool, bool: True if successful. False if already exists and not forced to overwrite.
            str, str: The filepaths where the private key and the public key have been saved.
        """
        # algorithm supported
        if alg not in ["RSA", "ED25519", "ECDSA", "DSA"]:
            raise Exception("SSH algorithm not supported by cryptopyutils")

        # private key files
        # case of elliptic curves
        if alg == "RSA":
            pkfp = os.path.join(dir, "ssh_host_rsa_key")
            # generate and save the private key
            self.gen_private_key("RSA", key_size, public_exponent)
        elif alg == "ED25519":
            pkfp = os.path.join(dir, "ssh_host_ed25519_key")
            self.gen_private_key("ED25519")
        elif alg == "ECDSA":
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
            pkfp = os.path.join(dir, "ssh_host_ecdsa_key")
            self.gen_private_key("EC", curve=curve)
        elif alg == "DSA":
            pkfp = os.path.join(dir, "ssh_host_dsa_key")
            self.gen_private_key(
                "DSA",
                config.DEFAULT_SSH_DSA_KEY_SIZE,
                config.DEFAULT_SSH_RSA_PUBLIC_EXPONENT,
            )
        else:
            # Not supported
            return None

        # save the private key
        status, priv = self.save_private_key(pkfp, passphrase, None, mode, force)
        # return False if private key not saved
        if status is False:
            return [False, ""], [pkfp, ""]
        # generate the public key
        self.gen_public_key()
        # generate public key filepath
        pubkfp = pkfp + ".pub"
        # save the public key
        status, pub = self.save_public_key(pubkfp, None, mode, force, comment)
        # return False if public key not saved
        if status is False:
            return [True, False], [pkfp, ""]
        # else return
        return [True, True], [pkfp, pubkfp]
