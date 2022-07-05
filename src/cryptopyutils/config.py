# -*- coding: utf-8 -*-
"""
config.py - Configuration file

Configuration of defaults

You can update the config according to your needs.

"""
import os
import platform
import sys
from os.path import expanduser

import distro


class Base:
    """Base object"""

    def copyobj(self, source):
        """Copy attributes from a source object

        Args:
            source (obj): source object
        Returns:
            obj: self
        """
        self.__dict__.update(source.__dict__)
        return self


class SysConfig(Base):
    """System Configuration - system information - extends Base"""

    def __init__(self, **kwargs):
        self.operating_system = os.name
        self.sys_platform = sys.platform
        self.platform_system = platform.system()
        self.platform_release = platform.release()
        if self.platform_system in ["Linux"]:
            self.distro = distro.id()
        else:
            self.distro = None


class ProjConfig(Base):
    """Project Configuration - extends SysConfig"""

    def __init__(self, **kwargs):
        self.sysconfig = kwargs.pop("sysconfig", SysConfig())
        # Default host
        self.host = kwargs.pop("host", "localhost")
        # Default output directory
        self.output_directory = kwargs.pop("output_directory", expanduser("~"))
        # Default file_mode
        self.file_mode = kwargs.pop("file_mode", 0o700)


class PasswordConfig(ProjConfig):
    """Password Configuration class - extends ProjConfig"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.salt_length = kwargs.pop("salt_length", 16)
        self.key_length = kwargs.pop("key_length", 32)
        self.salt_iterations = kwargs.pop("salt_iterations", 390000)


class HashConfig(Base):
    """Hash Configuration class - extends Base"""

    def __init__(self, **kwargs):
        # Warning: Avoid SHA1, MD5 or SHA less than 256, or SM3 (China)
        self.hash_algorithm = kwargs.pop("hash_algorithm", "SHA-256")


class AsymConfig(ProjConfig):
    """Asymmetric Configuration class - extends ProjConfig"""

    def __init__(self, **kwargs):
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
    """Private Key Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())
        # Default directory
        if not hasattr(self, "ssl_private_key_dir"):
            self.ssl_private_key_dir = kwargs.pop("ssl_private_key_dir", None)
        if self.ssl_private_key_dir is None:
            self.set_ssl_private_key_dir()
        # Default private key file mode
        self.private_key_mode = kwargs.pop("private_key_mode", 0o700)
        # Default private encoding
        self.private_encoding = kwargs.pop("private_encoding", self.asymconfig.encoding)
        # Default private format
        self.private_format = kwargs.pop("private_format", "PKCS8")
        # Default key sizes
        # RSA Key Size - Minimum should be 2048 bits.
        self.rsa_key_size = kwargs.pop("rsa_key_size", 4096)
        # RSA Public Exponent - 65537
        self.rsa_key_exponent = kwargs.pop("rsa_key_exponent", 65537)
        # DSA - Minimum 1024 bits
        self.dsa_key_size = kwargs.pop("dsa_key_size", 4096)
        # Elliptic Curves - NIST P-256 and P-384 are okay (with caveats)
        # Ed25519 is great alternative
        # https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/
        # https://malware.news/t/everyone-loves-curves-but-which-elliptic-curve-is-the-most-popular/17657
        self.elliptic_curve = "SECP384R1"

    def set_ssl_private_key_dir(self, path=None):
        """Set the SSL private key directory

        Args:
            path (str: optional): Path to the SSL private key directory.
            Defaults to None.
        """
        if path is not None:
            self.ssl_private_key_dir = path
        else:
            self.ssl_private_key_dir = os.path.join(self.asymconfig.ssl_dir, "private")


class PublicKeyConfig(Base):
    """Public Key Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())
        # Default directory
        if not hasattr(self, "ssl_public_key_dir"):
            self.ssl_public_key_dir = kwargs.pop("ssl_public_key_dir", None)
        if self.ssl_public_key_dir is None:
            self.set_ssl_public_key_dir()
        # Default public key file mode
        self.public_key_mode = kwargs.pop("public_key_mode", 0o744)
        # Default public encoding
        self.public_encoding = kwargs.pop("public_encoding", self.asymconfig.encoding)
        # Default public format
        self.public_format = kwargs.pop("private_format", "PKCS8")
        # Default public format
        self.public_format = kwargs.pop("public_format", "SubjectPublicKeyInfo")

    def set_ssl_public_key_dir(self, path=None):
        """Set the SSL public key directory

        Args:
            path (str: optional): Path to the SSL public key directory.
            Defaults to None.
        """
        if path is not None:
            self.ssl_public_key_dir = path
        else:
            self.ssl_public_key_dir = os.path.join(self.asymconfig.ssl_dir, "private")


class X509Config(AsymConfig):
    """x509 Configuration - extends AsymConfig"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())


class CertConfig(X509Config):
    """x509 Certificate Configuration - extends x509Config"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Default directory
        if not hasattr(self, "ssl_cert_dir"):
            self.ssl_cert_dir = kwargs.pop("ssl_cert_dir", None)
        if self.ssl_cert_dir is None:
            self.set_ssl_cert_dir()
        # Self-signed mode False by default
        self.self_signed = kwargs.pop("cert_self_signed", "False")
        # Default cert file mode
        self.cert_file_mode = kwargs.pop("cert_file_mode", 0o744)
        # Default encoding
        self.cert_encoding = kwargs.pop("cert_encoding", "PEM")
        # Default expiration in days
        self.cert_expiration_days = kwargs.pop("cert_expiration_days", 3650)
        # Certificate authority : False = Not a certificat authority,
        # cannot sign other certificates
        if self.self_signed:
            self.cert_ca = kwargs.pop("cert_ca", False)
        else:
            self.cert_ca = kwargs.pop("cert_ca", True)
        # Default cert DNS Names
        if self.self_signed:
            # Bug fix: 127.0.0.1 needed in DNS names
            self.cert_dns_names = kwargs.pop(
                "cert_dns_names",
                ["localhost", "127.0.0.1"],
            )
        else:
            self.cert_dns_names = kwargs.pop("cert_dns_names", [])
        # Default cert IP addresses
        if self.self_signed:
            self.cert_ip_addrs = kwargs.pop("cert_ip_addrs", ["127.0.0.1"])
        else:
            self.cert_ip_addrs = kwargs.pop("cert_ip_addrs", [])
        # Critical: Are DNS Names and IP Addrs an important part of the certificate
        self.cert_critical = kwargs.pop("cert_critical", True)
        # Path Length : Can be 1 if CA=True
        if self.cert_ca:
            self.cert_path_length = kwargs.pop("cert_path_length", 1)
        else:
            self.cert_path_length = kwargs.pop("cert_path_length", None)

    def set_ssl_cert_dir(self, path=None):
        """Set the SSL Certificate directory

        Args:
            path (str: optional): Path to the SSL certificate directory.
            Defaults to None.
        """
        if path is not None:
            self.ssl_cert_dir = path
        else:
            self.ssl_cert_dir = os.path.join(self.asymconfig.ssl_dir, "certs")


class CSRConfig(X509Config):
    """x509 CSR Configuration - extends x509Config"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Default directory
        if not hasattr(self, "ssl_csr_dir"):
            self.ssl_csr_dir = kwargs.pop("ssl_csr_dir", None)
        if self.ssl_csr_dir is None:
            self.set_ssl_csr_dir()
        # Default csr file mode
        self.csr_file_mode = kwargs.pop("csr_file_mode", 0o744)
        # Default encoding
        self.csr_encoding = kwargs.pop("csr_encoding", "PEM")
        # Default CSR DNS names
        self.csr_dns_names = kwargs.pop("csr_dns_names", [])
        # Default cert IP addresses
        self.csr_ip_addrs = kwargs.pop("csr_ip_addrs", [])
        # Critical: Are DNS Names and IP Addrs an important part of the certificate
        self.csr_critical = kwargs.pop("csr_critical", True)

    def set_ssl_csr_dir(self, path=None):
        """Set the SSL CSR directory

        Args:
            path (str: optional): Path to the SSL CSR directory. Defaults to None.
        """
        if path is not None:
            self.ssl_csr_dir = path
        else:
            self.ssl_csr_dir = os.path.join(self.asymconfig.ssl_dir, "csr")


class KeyPairConfig(Base):
    """Key Pair Configuration - extends Base"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())
        # Private key config
        self.pk_config = kwargs.pop("pk_config", PrivateKeyConfig())
        # Public key config
        self.pubk_config = kwargs.pop("pubk_config", PublicKeyConfig())


class SSHConfig(Base):
    """Configuration for SSH"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Projet configuration
        self.asymconfig = kwargs.pop("asymconfig", AsymConfig())
        # Private key config
        self.pk_config = kwargs.pop("pk_config", PrivateKeyConfig())
        # Public key config
        self.pubk_config = kwargs.pop("pubk_config", PublicKeyConfig())
        # Default SSL Directories
        self.set_user_dir()
        self.set_host_dir()
        # Variables
        self.pk_config.dsa_key_size = 1024

    def set_user_dir(self, path=None):
        """Set the SSH user directory

        Args:
            path (str: optional): Path to the SSH user directory. Defaults to None.
        """
        if path is not None:
            self.user_dir = path
        else:
            self.user_dir = os.path.join(expanduser("~"), "/.ssh")

    def set_host_dir(self, path=None):
        """Set the SSH host directory

        Args:
            path (str: optional): Path to the SSH host directory. Defaults to None.
        """
        if path is not None:
            self.host_dir = path
        else:
            self.host_dir = "/etc/host"
