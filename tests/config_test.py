# -*- coding: utf-8 -*-
"""Test config.py
"""
from cryptopyutils import config


def test_copy_base_config():
    """Test config.Base"""
    beta = config.Base(test=10, test1=11)
    alpha = config.Base()
    alpha.test = None
    alpha.test1 = None
    alpha.copy(beta)
    assert alpha.test == 10
    assert alpha.test1 == 11


def test_sys_config_attributes():
    """Test config.SysConfig"""
    beta = config.SysConfig()
    assert hasattr(beta, "operating_system")
    assert hasattr(beta, "sys_platform")
    assert hasattr(beta, "platform_release")
    assert hasattr(beta, "distro")


def test_sys_config_copy():
    """Test copy method of config.SysConfig"""
    alpha = config.Base()
    alpha.distro = "TEST"
    beta = config.SysConfig().copy(alpha)
    assert beta.distro == "TEST"


def proj_config_attributes():
    """Test ProjConfig attributes"""
    alpha = config.ProjConfig()
    assert hasattr(alpha, "sysconfig")
    assert isinstance(alpha.sysconfig, config.SysConfig)
    assert hasattr(alpha.sysconfig, "operating_system")
    assert hasattr(alpha.sysconfig, "sys_platform")
    assert hasattr(alpha.sysconfig, "platform_release")
    assert hasattr(alpha.sysconfig, "distro")
    assert hasattr(alpha, "host")
    assert hasattr(alpha, "output_dir")
    assert hasattr(alpha, "file_mode")


def test_proj_config_copy():
    """Test copy of ProjConfig"""
    alpha = config.ProjConfig()
    alpha.sysconfig.distro = "TEST"
    beta = config.ProjConfig().copy(alpha)
    assert beta.sysconfig.distro == "TEST"


def test_password_config_attributes():
    """Test PasswordConfig attributes"""
    alpha = config.PasswordConfig()
    assert hasattr(alpha, "hash_algorithm")
    assert hasattr(alpha, "salt_length")
    assert hasattr(alpha, "key_length")
    assert hasattr(alpha, "iterations")


def test_asymconfig():
    """Test AsymConfig attributes"""
    alpha = config.AsymConfig()
    assert hasattr(alpha, "priv_key_alg")
    assert hasattr(alpha, "ssl_dir")
    assert hasattr(alpha, "encoding")
    assert hasattr(alpha, "hash_alg")
    assert alpha.ssl_dir in ["/etc/ssl", "/etc/pki/tls"]


def test_private_key_config():
    """Test PrivateKeyConfig attributes"""
    alpha = config.PrivateKeyConfig()
    assert hasattr(alpha, "ssl_dir")
    assert hasattr(alpha, "encoding")
    assert hasattr(alpha, "alg")
    assert hasattr(alpha, "hash_alg")
    assert hasattr(alpha, "key_dir")
    assert hasattr(alpha, "file_mode")
    assert hasattr(alpha, "file_format")
    assert hasattr(alpha, "rsa_key_size")
    assert hasattr(alpha, "rsa_public_exponent")
    assert hasattr(alpha, "dsa_key_size")
    assert hasattr(alpha, "elliptic_curve")
    assert alpha.key_dir.index("private") > -1


def test_public_key_config():
    """Test PublicKeyConfig attributes"""
    alpha = config.PublicKeyConfig()
    assert hasattr(alpha, "ssl_dir")
    assert hasattr(alpha, "encoding")
    assert hasattr(alpha, "alg")
    assert hasattr(alpha, "hash_alg")
    assert hasattr(alpha, "key_dir")
    assert hasattr(alpha, "file_mode")
    assert hasattr(alpha, "file_format")
    assert alpha.key_dir.index("public") > -1


def test_x509_config():
    """Test X509Config attributes"""
    alpha = config.X509Config()
    assert hasattr(alpha, "asymconfig")
    assert isinstance(alpha.asymconfig, config.AsymConfig)


def test_cert_config():
    """Test CertConfig"""
    alpha = config.CertConfig()
    assert hasattr(alpha, "asymconfig")
    assert hasattr(alpha, "hash_alg")
    assert hasattr(alpha, "cert_dir")
    assert hasattr(alpha, "self_signed")
    assert hasattr(alpha, "file_mode")
    assert hasattr(alpha, "encoding")
    assert hasattr(alpha, "expiration_days")
    assert hasattr(alpha, "cert_auth")
    assert hasattr(alpha, "dns_names")
    assert hasattr(alpha, "ip_addrs")
    assert hasattr(alpha, "critical")
    assert hasattr(alpha, "path_length")
    assert alpha.cert_dir.index("certs") > -1


def test_cert_config_self_signed():
    """Test CertConfig with self signed"""
    alpha = config.CertConfig(self_signed=True)
    assert alpha.self_signed is True
    assert alpha.cert_auth is False
    assert alpha.path_length is None
    assert alpha.dns_names == ["localhost", "127.0.0.1"]
    assert alpha.ip_addrs == ["127.0.0.1"]


def test_csr_config():
    """Test CSRConfig"""
    alpha = config.CSRConfig()
    assert hasattr(alpha, "asymconfig")
    assert hasattr(alpha, "hash_alg")
    assert isinstance(alpha.asymconfig, config.AsymConfig)
    assert hasattr(alpha, "csr_dir")
    assert hasattr(alpha, "file_mode")
    assert hasattr(alpha, "encoding")
    assert hasattr(alpha, "dns_names")
    assert hasattr(alpha, "ip_addrs")
    assert alpha.csr_dir.index("csr") > -1


def test_sshkey_pair_config():
    """Test SSHKeyPair Config"""
    alpha = config.SSHKeyPairConfig()
    assert alpha.dsa_key_size == 1024
    assert hasattr(alpha, "hash_alg")
    assert hasattr(alpha, "user_dir")
    assert alpha.user_dir.index(".ssh") > -1
    assert hasattr(alpha, "host_dir")
    assert alpha.host_dir.index("/etc/ssh") > -1
