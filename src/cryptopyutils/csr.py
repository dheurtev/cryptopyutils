# -*- coding: utf-8 -*-
"""csr.py - Certificate Signing Request (CSR)

Class:

* CSR : x509 CSR object

"""
from cryptography import x509
from cryptography.x509.oid import AttributeOID

from . import files
from . import utils
from .cert import _Commonx509
from .config import Base
from .config import CSRConfig


class CSR(Base):
    """CSR Object extends Base

    Usage:

    * initialize : c = CSR() or c = CSR(private_key=PrivateKey())
    * generate csr : c.gen()
    * get csr object : c.csr
    * save csr: c.save(filepath)
    * load keycsr: c.load(filepath)
    """

    def __init__(self, **kwargs):
        """CSR init
        Args:
            config (CSRConfig, optional): The configuration.
            private_key (PrivateKey, optional): The private key. An instance of PrivateKey.
                Defaults to None.
            csr (CSR, optional): An instance of CSR.
                Defaults to None.

        """
        super().__init__(**kwargs)
        # configuration
        if not hasattr(self, "config"):
            self._config = kwargs.pop(
                "config",
                CSRConfig(),
            )
        # private key
        if not hasattr(self, "private_key"):
            self._private_key = kwargs.pop("private_key", None)
        # csr
        if not hasattr(self, "csr"):
            self._csr = kwargs.pop("csr", None)

    @property
    def csr(self):
        """Get the CSR attribute

        Returns:
            Cryptography CSR: An instance of CSR from Cryptography.

        """
        return self._csr

    @csr.setter
    def csr(self, csr):
        """Set the csr with a pre-existing CSR

        Args:
            csr (Cryptography CSR): An instance of CSR from Cryptography
        """
        self._csr = csr

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

    # Generate

    def gen(
        self,
        challenge_password,
        subject=None,
        dns_names=None,
        ip_addresses=None,
        hash_alg=None,
    ):
        """Generate a x509 CSR

        Args:
            challenge_password(str or bytes): The secret shared with the certificate issuer.
            String will be encoded in UTF8.
            subject: dict(str, optional): The subject informations needed to generate
                the CSR.
                Defaults to None.
            dns_names (list(str), optional): A list of DNS Names.
                Defaults to None.
            ip_addresses: list(str, optional): A list of IP addresses.
                Defaults to None.
            hash_alg (str, optional): The Hash algorithm.
                Defaults to None.

        """
        # defaults
        if subject is None:
            subject = self._config.subject
        if dns_names is None:
            dns_names = self._config.dns_names
        if ip_addresses is None:
            ip_addresses = self._config.ip_addrs
        if hash_alg is None:
            hash_alg = self._config.hash_alg
        # build the distinguished names
        subject_obj = x509.Name(_Commonx509().build_name_attributes(subject))
        # Generate a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject_obj)
        if len(dns_names) > 0:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    _Commonx509().build_subject_alternative_names(
                        dns_names,
                        ip_addresses,
                    ),
                ),
                critical=True,
            )
        # Add basic constraints
        basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
        builder = builder.add_extension(basic_contraints, critical=True)
        # Add the challenge password
        if isinstance(challenge_password, str):
            challenge_pwd = bytes(challenge_password.encode("UTF-8"))
        else:
            challenge_pwd = challenge_password
        builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge_pwd)
        # Sign the CSR with our private key.
        self._csr = builder.sign(self.private_key.key, utils.hash_algorithm(hash_alg))

    # Save

    def save(
        self,
        path,
        file_mode=None,
        encoding=None,
        force=False,
    ):
        """Write our x509 CSR out to disk

        Args:
            path(str): The file path where the CSR will be saved.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            encoding (str, optional): Encoding PEM or DER.
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        # Defaults
        if file_mode is None:
            file_mode = self._config.file_mode

        if encoding is None:
            encoding = self._config.encoding

        # encoding
        enc = utils.file_encoding(encoding)
        # serialize the csr
        data = self._csr.public_bytes(enc)
        # early return no overwriting if exists and not forced
        if files.file_exists(path) and (not force):
            return False
        # write file and create directories
        files.write(path, data)
        # set keymode
        files.set_chmod(path, file_mode)
        # return True
        return True

    def save_pem(
        self,
        path,
        file_mode=None,
        force=False,
    ):
        """Write our PEM x509 CSR out to disk

        Args:
            path(str): The file path where the CSR will be saved.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, file_mode, "PEM", force)

    def save_der(
        self,
        path,
        file_mode=None,
        force=False,
    ):
        """Write our DER x509 CSR out to disk

        Args:
            path(str, optional): The file path where the CSR will be saved.
            file_mode (byte, optional): The file mode (chmod).
                Defaults to None.
            force (bool, optional): Force to replace file if already exists.
                Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced
                to overwrite.

        """
        return self.save(path, file_mode, "DER", force)

    # Load
    def load(self, path, encoding=None):
        """Load the CSR the disk

        Args:
            path (str): The file path where the CSR is saved.
            encoding (str, optional): Encoding PEM or DER.
                Defaults to None.
        """
        # Defaults
        if encoding is None:
            encoding = self._config.encoding
        # Read the file
        data = files.read(path)
        # Load the file
        if encoding == "PEM":
            self._csr = x509.load_pem_x509_csr(data)
        else:
            self._csr = x509.load_der_x509_csr(data)

    def load_pem(self, path):
        """Load the PEM x509 CSR from the disk

        Args:
            filepath (str): The file path where the CSR is saved.

        """
        self.load(path, "PEM")

    def load_der(self, path):
        """Load the DER x509 CSR from the disk

        Args:
            path (str): The file path where the CSR is saved.

        """
        self.load(path, "DER")
