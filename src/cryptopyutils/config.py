# -*- coding: utf-8 -*-
"""config.py - Configuration file

Configuration of defaults

You can update the config according to your needs.

"""
import os
import platform
import sys
from os.path import expanduser

import distro


class Base:
    """Base class"""

    def __init__(self, **kwargs):
        """Base class initiator"""
        for attr, value in kwargs.items():
            self.__setattr__(attr, value)

    def copy(self, source):
        """Copy attributes from a source object

        Args:
            source (obj): source object

        Returns:
            obj: self

        """
        self.__dict__.update(source.__dict__)
        return self


class SysConfig(Base):
    """SysConfig class - System Configuration - system information - extends Base"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.operating_system = os.name
        self.sys_platform = sys.platform
        self.platform_system = platform.system()
        self.platform_release = platform.release()
        if self.platform_system in ["Linux"]:
            self.distro = distro.id()
        else:
            self.distro = None


class ProjConfig(Base):
    """Projconfig class - Project Configuration - extends SysConfig"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sysconfig = kwargs.pop("sysconfig", SysConfig())
        # Default host
        self.host = kwargs.pop("host", "localhost")
        # Default output directory
        self.output_directory = kwargs.pop("output_directory", expanduser("~"))
        # Default file_mode
        self.file_mode = kwargs.pop("file_mode", 0o600)


class PasswordConfig(Base):
    """PasswordConfig class - Password Configuration class - extends Base

    Args:
        hash_algorithm (str): the name of the hash algorithm.
            Defaults to SHA-256.
        salt_length (int) – The number of bytes of the salt.
            Secure values are 16 (128-bits) or longer and randomly generated.
            Defaults to 16.
        length (int) – The desired length of the derived key in bytes.
            Maximum is (232 - 1) * algorithm.digest_size.
            Defaults to 32.
        iterations (int) – The number of iterations to perform of the
            hash function.
            This can be used to control the length of time the operation takes.
            Higher numbers help mitigate brute force attacks against derived keys.
            Defaults to 390000.
    """

    def __init__(self, **kwargs):
        """ "PasswordConfig class initiator"""
        super().__init__(**kwargs)
        self.hash_algorithm = kwargs.pop("hash_algorithm", "SHA-256")
        self.salt_length = kwargs.pop("salt_length", 16)
        self.key_length = kwargs.pop("key_length", 32)
        self.iterations = kwargs.pop("iterations", 390000)


class AsymConfig(ProjConfig):
    """AsymConfig class - Asymmetric Configuration class - extends ProjConfig"""

    def __init__(self, **kwargs):
        """AsymConfig class initiator"""
        super().__init__(**kwargs)
        # Default algorithm
        self.priv_key_alg = kwargs.pop("priv_key_alg", "rsa")
        # Default SSL Directories
        if not hasattr(self, "ssl_dir"):
            self.ssl_dir = kwargs.pop("ssl_dir", None)
        if self.ssl_dir is None:
            self.set_ssl_dir()
        # Default encoding
        self.encoding = kwargs.pop("encoding", "PEM")
        # Hash algorithm
        self.hash_alg = kwargs.pop("hash_alg", "SHA-256")

    def set_ssl_dir(self, path=None):
        """Set the SSL directory

        Args:
            path (str, optional): Path to the SSL directory. Defaults to None.

        Returns:
            str: The path to the ssl directory

        """
        if path is not None:
            self.ssl_dir = path
        else:
            # Default SSL directories
            if self.sysconfig.distro in [
                "ubuntu",
                "debian",
                "linuxmint",
                "raspbian",
                "sles",
                "opensuse",
                "arch",
                "gentoo",
                "exherbo",
                "slackware",
            ]:
                self.ssl_dir = "/etc/ssl"
            elif self.sysconfig.distro in [
                "rhel",
                "centos",
                "fedora",
                "amazon",
                "oracle",
                "scientific",
                "cloudlinux",
                "xenserver",
                "pidora",
                "mageia",
                "mandriva",
            ]:
                self.ssl_dir = "/etc/pki/tls"
            elif self.sysconfig.distro in ["openbsd", "netbsd", "freebsd"]:
                self.ssl_dir = "/etc/ssl"
            else:
                self.ssl_dir = "/etc/ssl"
        return self.ssl_dir


class PrivateKeyConfig(Base):
    """PrivateKeyConfig class - Private Key Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        """PrivateKeyConfig class initiator"""
        super().__init__(**kwargs)
        # SSL Directory
        self.ssl_dir = kwargs.pop("ssl_dir", "/etc/ssl")
        # Default directory
        if not hasattr(self, "key_dir"):
            self.key_dir = kwargs.pop("key_dir", None)
        if self.key_dir is None:
            self.set_key_dir()
        # Default algorithm
        self.alg = kwargs.pop("alg", "RSA")
        # Default file mode
        self.file_mode = kwargs.pop("file_mode", 0o600)
        # Default encoding
        self.encoding = kwargs.pop("encoding", "PEM")
        # Default file format
        self.file_format = kwargs.pop("file_format", "PKCS8")
        # Default key sizes
        # RSA Key Size - Minimum should be 2048 bits.
        self.rsa_key_size = kwargs.pop("rsa_key_size", 4096)
        # RSA Public Exponent - 65537
        self.rsa_public_exponent = kwargs.pop("rsa_public_exponent", 65537)
        # DSA - Minimum 1024 bits
        self.dsa_key_size = kwargs.pop("dsa_key_size", 4096)
        # Elliptic Curves - NIST P-256 and P-384 are okay (with caveats)
        # Ed25519 is great alternative
        # https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/
        # https://malware.news/t/everyone-loves-curves-but-which-elliptic-curve-is-the-most-popular/17657
        self.elliptic_curve = "SECP384R1"
        # Hash algorithm
        self.hash_alg = kwargs.pop("hash_alg", "SHA-256")

    def set_key_dir(self, path=None):
        """Set the SSL private key directory

        Args:
            path (str: optional): Path to the SSL private key directory.
                Defaults to None.
        """
        if path is not None:
            self.key_dir = path
        else:
            self.key_dir = os.path.join(self.ssl_dir, "private")


class PublicKeyConfig(Base):
    """PublicKeyConfig initiator - Public Key Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        """PublicKeyConfig class initiator"""
        super().__init__(**kwargs)
        # SSL Directory
        self.ssl_dir = kwargs.pop("ssl_dir", "/etc/ssl")
        # Default directory
        if not hasattr(self, "ssl_key_dir"):
            self.key_dir = kwargs.pop("key_dir", None)
        if self.key_dir is None:
            self.set_key_dir()
        # Default algorithm
        self.alg = kwargs.pop("alg", "RSA")
        # Default file mode
        self.file_mode = kwargs.pop("file_mode", 0o644)
        # Default public encoding
        self.encoding = kwargs.pop("encoding", "PEM")
        # Default file format
        self.file_format = kwargs.pop("file_format", "PKCS8")
        # Default file format
        self.file_format = kwargs.pop("file_format", "SubjectPublicKeyInfo")
        # Hash algorithm
        self.hash_alg = kwargs.pop("hash_alg", "SHA-256")

    def set_key_dir(self, path=None):
        """Set the SSL public key directory

        Args:
            path (str: optional): Path to the SSL public key directory.
                Defaults to None.
        """
        if path is not None:
            self.key_dir = path
        else:
            self.key_dir = os.path.join(self.ssl_dir, "public")


class X509Config(AsymConfig):
    """X509Config class - x509 Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        """X509Config class initiator"""
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())
        # Issuer
        self.issuer = {
            "COMMON_NAME": "www.example.com",
            "LOCALITY_NAME": "San Francisco",
            "STATE_OR_PROVINCE_NAME": "California",
            "ORGANIZATION_NAME": "Example inc",
            "ORGANIZATIONAL_UNIT_NAME": "Example Division",
            "COUNTRY_NAME": "US",
            "STREET_ADDRESS": "0000 Acme Road",
        }
        self.subject = self.issuer


class CertConfig(X509Config):
    """CertConfig class - x509 Certificate Configuration - extends x509Config"""

    def __init__(self, **kwargs):
        """CertConfig class initiator"""
        super().__init__(**kwargs)
        # Default directory
        if not hasattr(self, "cert_dir"):
            self.cert_dir = kwargs.pop("cert_dir", None)
        if self.cert_dir is None:
            self.set_cert_dir()
        # Self-signed mode False by default
        self.self_signed = kwargs.pop("self_signed", False)
        # Default file mode
        self.file_mode = kwargs.pop("file_mode", 0o644)
        # Default encoding
        self.encoding = kwargs.pop("encoding", "PEM")
        # Default expiration in days
        self.expiration_days = kwargs.pop("expiration_days", 3650)
        # Certificate authority : False = Not a certificat authority,
        # cannot sign other certificates
        if self.self_signed:
            self.cert_auth = kwargs.pop("cert_auth", False)
        else:
            self.cert_auth = kwargs.pop("cert_auth", True)
        # Default DNS Names
        if self.self_signed:
            # Bug fix: 127.0.0.1 needed in DNS names
            self.dns_names = kwargs.pop(
                "dns_names",
                ["localhost", "127.0.0.1"],
            )
        else:
            self.dns_names = kwargs.pop("dns_names", [])
        # Default IP addresses
        if self.self_signed:
            self.ip_addrs = kwargs.pop("ip_addrs", ["127.0.0.1"])
        else:
            self.ip_addrs = kwargs.pop("ip_addrs", [])
        # Critical: Are DNS Names and IP Addrs an important part of the certificate
        self.critical = kwargs.pop("critical", True)
        # Path Length : Can be 1 if CA=True
        if self.cert_auth:
            self.path_length = kwargs.pop("path_length", 1)
        else:
            self.path_length = kwargs.pop("path_length", None)

    def set_cert_dir(self, path=None):
        """Set the SSL Certificate directory

        Args:
            path (str: optional): Path to the SSL certificate directory.
                Defaults to None.

        """
        if path is not None:
            self.cert_dir = path
        else:
            self.cert_dir = os.path.join(self.asymconfig.ssl_dir, "certs")


class CSRConfig(X509Config):
    """CSRConfig class - x509 CSR Configuration - extends x509Config"""

    def __init__(self, **kwargs):
        """CSRConfig class initiator"""
        super().__init__(**kwargs)
        # Default directory
        if not hasattr(self, "csr_dir"):
            self.ssl_csr_dir = kwargs.pop("csr_dir", None)
        if self.ssl_csr_dir is None:
            self.set_csr_dir()
        # Default file mode
        self.file_mode = kwargs.pop("file_mode", 0o644)
        # Default encoding
        self.encoding = kwargs.pop("encoding", "PEM")
        # Default DNS names
        self.dns_names = kwargs.pop("dns_names", [])
        # Default IP addresses
        self.ip_addrs = kwargs.pop("ip_addrs", [])

    def set_csr_dir(self, path=None):
        """Set the SSL CSR directory

        Args:
            path (str: optional): Path to the SSL CSR directory. Defaults to None.
        """
        if path is not None:
            self.csr_dir = path
        else:
            self.csr_dir = os.path.join(self.asymconfig.ssl_dir, "csr")


class SSHKeyPairConfig(Base):
    """SSHKeyPairConfig class - Configuration for SSH Key Pair"""

    def __init__(self, **kwargs):
        """SSHKeyPairConfig class initiator"""
        super().__init__(**kwargs)
        # Default SSL Directories
        self.set_user_dir()
        self.set_host_dir()
        # Variables
        self.dsa_key_size = 1024
        # Hash algorithm
        self.hash_alg = kwargs.pop("hash_alg", "SHA-256")

    def set_user_dir(self, path=None):
        """Set the SSH user directory

        Args:
            path (str: optional): Path to the SSH user directory.
                Defaults to None.

        """
        if path is not None:
            self.user_dir = path
        else:
            self.user_dir = os.path.join(expanduser("~"), "/.ssh")

    def set_host_dir(self, path=None):
        """Set the SSH host directory

        Args:
            path (str: optional): Path to the SSH host directory.
                Defaults to None.

        """
        if path is not None:
            self.host_dir = path
        else:
            self.host_dir = "/etc/ssh"
