# -*- coding: utf-8 -*-
"""cert.py - x509 Certificates

Class:
- Commonx509: Build certificate attribute names and name attributes
- Certificate : Load, generate, save x509 Certificates

"""
import base64
import binascii
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from . import dirs
from . import files
from . import utils
from .config import Base
from .config import CertConfig


class _Commonx509:
    """Internal Commonx509 Object"""

    # Common

    def build_subject_alternative_names(self, dns_names, ip_addresses):
        """Build a list of x509.DNSName objects

        Args:
            dns_names: list(str): A list of DNS Names.
            ip_addresses: list(str): A list of IP Addresses.

        Returns:
            list: The list of x509.DNSName objects.
        """
        alt_names = []
        for dnsname in dns_names:
            alt_names.append(x509.DNSName(str(dnsname)))
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(str(addr))))
        return alt_names

    def build_name_attributes(self, name_attributes):
        """Build a list of x509.NameAttribute

        Args:
            name_attributes dict(str, str): A dict of name attributes.

        Returns:
            list: The list of x509.NameAttribute objects
        """
        nameattrs = []
        for item in name_attributes:
            oid = NameOID.__getattribute__(item)
            nameattrs.append(x509.NameAttribute(oid, name_attributes[item]))
        return nameattrs


class Certificate(Base):
    """Certificate Object - extends Base

    Usage:
    - initialize : c = Certificate(private_key=PrivateKey())
    - generate cert : c.gen(**kwargs)
    - generate self-signed cert : c.gen_self_signed(**kwargs)
    - get certificate object : c.cert
    - save cert: c.save(filepath)
    - load cert: c.load(filepath)
    """

    def __init__(self, **kwargs):
        """Certificate init
        Args:
            config (CertConfig, optional): The configuration.
            private_key (PrivateKey): The private key. An instance of PrivateKey.
            Defaults to None.
            self_signed(bool): Is the certificate self_signed.
            Defaults to False
        """
        super().__init__(**kwargs)
        # configuration
        if not hasattr(self, "self_signed"):
            self._self_signed = kwargs.pop("self_signed", False)

        if not hasattr(self, "config"):
            self._config = kwargs.pop(
                "config",
                CertConfig(self_signed=self._self_signed),
            )
        # private key
        if not hasattr(self, "private_key"):
            self._private_key = kwargs.pop("private_key", None)
        # cert
        if not hasattr(self, "cert"):
            self._cert = kwargs.pop("cert", None)

    # Generate
    def gen(
        self,
        issuer=None,
        subject=None,
        dns_names=None,
        ip_addresses=None,
        expiration_days=None,
        critical=None,
        hash_alg=None,
        cert_auth=None,
        path_length=None,
    ):
        """Generate a x509 certificate

        Args:
            issuer: dict(str): The issuer informations needed to generate
            the certificate.
            Defaults to None.
            subject: dict(str): The subject informations needed to generate
            the certificate.
            Defaults to None.
            dns_names (list(str), optional): A list of DNS Names.
            Defaults to None.
            ip_addresses: list(str): A list of IP addresses.
            Defaults to None.
            expiration_days (int): Number of days until the certificate expires.
            Defaults to None.
            critical (bool): Set to True if the extension must be understood and
            handled by whoever reads the certificate.
            Defaults to None.
            hash_alg (str): The Hash algorithm.
            Defaults to None.
            cert_auth (bool): Whether the certificate can sign certificates.
            Defaults to None.
            path_length (int or None): The maximum path length for certificates
            subordinate to this certificate. This attribute only has meaning if cert_auth
            is true. If cert_auth is true then a path length of None means there’s no
            restriction on the number of subordinate CAs in the certificate chain.
            If it is zero or greater then it defines the maximum length for a
            subordinate CA’s certificate chain. For example, a path_length of 1 means
            the certificate can sign a subordinate CA, but the subordinate CA is not
            allowed to create subordinates with ca set to true.
            Defaults to None.

        """
        # defaults
        if issuer is None:
            issuer = self._config.issuer
        if subject is None:
            subject = self._config.subject
        if dns_names is None:
            dns_names = self._config.dns_names
        if ip_addresses is None:
            ip_addresses = self._config.ip_addrs
        if expiration_days is None:
            expiration_days = self._config.expiration_days
        if critical is None:
            critical = self._config.critical
        if hash_alg is None:
            hash_alg = self._config.hash_alg
        if cert_auth is None:
            cert_auth = self._config.cert_auth
        if path_length is None:
            if self._self_signed == False:
                path_length = self._config.path_length
            else:
                path_length = None
        # build the distinguished names
        issuer_obj = x509.Name(_Commonx509().build_name_attributes(issuer))
        subject_obj = x509.Name(_Commonx509().build_name_attributes(subject))
        # build the certificate
        certb = (
            x509.CertificateBuilder()
            .subject_name(
                subject_obj,
            )
            .issuer_name(
                issuer_obj,
            )
            .public_key(
                self._private_key.key.public_key(),
            )
            .serial_number(
                x509.random_serial_number(),
            )
            .not_valid_before(
                datetime.datetime.utcnow(),
            )
            .not_valid_after(
                # Our certificate will be valid for the number of days set in expiration_days
                datetime.datetime.utcnow()
                + datetime.timedelta(days=expiration_days),
            )
        )
        # Add basic constraints
        basic_contraints = x509.BasicConstraints(ca=cert_auth, path_length=path_length)
        certb = certb.add_extension(basic_contraints, critical=critical)
        # Add DNS Names and IP addresses
        certb = certb.add_extension(
            x509.SubjectAlternativeName(
                _Commonx509().build_subject_alternative_names(dns_names, ip_addresses),
            ),
            critical=critical,
        )
        # Sign our certificate with our private key
        self._cert = certb.sign(self._private_key.key, utils.hash_algorithm(hash_alg))

    def gen_self_signed(
        self,
        subject=None,
        dns_names=None,
        ip_addresses=None,
        expiration_days=None,
        critical=True,
        hash_alg=None,
        certh_auth=False,
        path_length=None,
    ):
        """Generate a self signed x509 certificate

        Args:
            subject: dict(str): The issuer informations needed to generate the certificate.
            Subject also is the issuer for self-signed certificates.
            Defaults to None.
            subject: dict(str): The subject informations needed to generate the certificate.
            Defaults to None.
            dns_names (list(str), optional): A list of DNS Names.
            Defaults to None.
            ip_addresses: list(str): A list of IP addresses.
            Defaults to None.
            expiration_days (int): Number of days until the certificate expires.
            Defaults to None.
            critical (bool): Set to True if the extension must be understood and handled by whoever
            reads the certificate.
            Defaults to True for self signed.
            hash_alg (str): The Hash algorithm.
            Defaults to None.
            cert_auth (bool): Whether the certificate can sign certificates.
            Defaults to false for self signed.
            path_length (int or None): The maximum path length for certificates subordinate to this
            certificate. This attribute only has meaning if ca is true. If ca is true then a path
            length of None means there’s no restriction on the number of subordinate CAs in the
            certificate chain. If it is zero or greater then it defines the maximum length for a
            subordinate CA’s certificate chain. For example, a path_length of 1 means the
            certificate can sign a subordinate CA, but the subordinate CA is not allowed to create
            subordinates with ca set to true.
            Defaults None for self signed.

                See /?highlight=hashes#module-cryptography.hazmat.primitives.hashes
                Defaults to SHA256.
            cert_auth (bool): Whether the certificate can sign certificates. Defaults to False for
            self-signed certificate.
            path_length (int or None): The maximum path length for certificates subordinate to this
            certificate. This attribute only has meaning if ca is true. If ca is true then a path
            length of None means there’s no restriction on the number of subordinate CAs in the
            certificate chain. If it is zero or greater then it defines the maximum length for a
            subordinate CA’s certificate chain. For example, a path_length of 1 means the
            certificate can sign a subordinate CA, but the subordinate CA is not allowed to create
            subordinates with ca set to true. Defaults to 1.

        Returns:
            x509.Certificate: The x509 Certificate. An instance of x509.Certificate.
        """
        # subject and issuers are the same
        self.gen(
            subject,
            subject,
            dns_names,
            ip_addresses,
            expiration_days,
            critical,
            hash_alg,
            certh_auth,
            path_length,
        )
        self._self_signed = True
        return self.cert

    # Save
    def save(
        self,
        path,
        file_mode=None,
        encoding=None,
        force=True,
    ):
        """Write our x509 certificate out to disk

        Args:
            path(str): The file path where the certificate will be saved.
            file_mode (byte, optional): The file mode (chmod).
            Defaults to None.
            encoding (str, optional): Encoding PEM or DER.
            Defaults to None.
            force (bool, optional): Force to replace file if already exists.
            Defaults to False.

        Returns:
            bool: True if successful. False if already exists and not forced to overwrite.
        """
        # Defaults
        if file_mode is None:
            file_mode = self._config.file_mode

        if encoding is None:
            encoding = self._config.encoding

        # encoding
        enc = utils.encoding(encoding)
        # serialize the certificate
        data = self._cert.public_bytes(enc)
        # early return no overwriting if exists and not forced
        if files.file_exists(self.path) and (not force):
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
        force=True,
    ):
        """Write our PEM x509 certificate out to disk

        Args:
            path(str, optional): The file path where the certificate will be saved.
            Default is None (will generate a temporary file).
            out_dir(str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_X509_CERT_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists.
            Defaults to True.

        Returns:
            bool: True if successful. False if already exists and not forced to overwrite.
            str: The filepath where the certificate has been saved.
        """
        return self.save(path, file_mode, "PEM", force)

    def save_der(
        self,
        path=None,
        file_mode=None,
        force=True,
    ):
        """Write our DER x509 certificate out to disk

        Args:
            path(str, optional): The file path where the certificate will be saved.
            Default is None (will generate a temporary file).
            out_dir(str, optional): The directory path.
            Defaults to the DEFAULT_OUTPUT_DIRECTORY value set in the config.py file.
            mode (byte, optional): The file mode (chmod).
            Defaults to the DEFAULT_X509_CERT_MODE value set in the config.py file.
            force (bool, optional): Force to replace file if already exists.
            Defaults to True.

        Returns:
            bool: True if successful. False if already exists and not forced to overwrite.
            str: The filepath where the certificate has been saved.
        """
        return self.save(path, file_mode, "DER", force)

    # Load
    def load(self, path, encoding=None):
        """Load the x509 certificate from the disk

        Args:
            path (str): The file path where the certificate is saved.
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
            self.cert = x509.load_pem_x509_certificate(data)
        else:
            self.cert = x509.load_der_x509_certificate(data)

    def load_pem(self, path):
        """Load the PEM x509 certificate from the disk

        Args:
            filepath (str): The file path where the certificate is saved.
        """
        return self.load(path, "PEM")

    def load_der(self, path):
        """Load the DER x509 certificate from the disk

        Args:
            path (str): The file path where the certificate is saved.
        """
        return self.load(path, "DER")

    def hash_fingerprint_pem_cert(
        self,
        path,
        hash_algorithm=None,
        b64output=False,
    ):
        """Get the fingerprint of a base64 PEM certificate based on a hash function

        Args:
            path (str): path to the base64 encoded PEM certificate file
            hash_algorithm (HashAlgorithm) – An instance of HashAlgorithm.
            Defaults to None.
            b64output (bool): If True, output is base64 format. If false, output is represented as heximals.
            Defaults to False
        """
        # Defaults
        if hash_alg is None:
            hash_alg = self._config.hash_alg
        # Read the cert
        data = files.read(path, istext=True)
        # Remove the start and the end
        data = data.replace("-----BEGIN CERTIFICATE-----\n", "")
        data = data.replace("-----END CERTIFICATE-----\n", "")
        # prepare the hash algorithm
        digest = hashes.Hash(utils.hash_algorithm(alg=hash_algorithm))
        # convert the base64 data to bytes
        databytes = binascii.a2b_base64(data)
        # compute the fingerprint, encode it to base 64, remove equal signs and add the hash alg
        digest.update(databytes)
        finaldigest = digest.finalize()
        if not b64output:
            fingerp = binascii.hexlify(finaldigest).decode()
        else:
            fingerp = base64.b64encode(finaldigest).decode()
            fingerp = fingerp.replace("=", "")
        # remove the dash from the hash algoritm
        hashalg = str(hash_algorithm).replace("-", "")
        # return the output
        return hashalg + ":" + fingerp
