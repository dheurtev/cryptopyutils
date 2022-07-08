# -*- coding: utf-8 -*-
""" Test suite : cert.py - x509 certificate
"""
import os

from cryptography import x509 as cryptx509
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.backends.openssl import x509
from cryptopyutils.cert import Certificate
from cryptopyutils.privatekey import PrivateKey


def test_instanciation_new_cert():
    """Test Certificate object instanciation with new certificate"""
    cert = Certificate()
    assert cert.cert is None


def test_instanciation_private_key_cert():
    """Test Certificate object instanciation with existing private key"""
    privk = PrivateKey()
    privk.gen()
    cert = Certificate(private_key=privk)
    cert.gen()
    assert isinstance(cert.cert, x509._Certificate)
    assert isinstance(cert.private_key, PrivateKey)
    assert isinstance(cert.private_key.key, rsa._RSAPrivateKey)


def test_instanciation_existing_cert():
    """Test Certificate object instanciation with existing certificate"""
    privk = PrivateKey()
    privk.gen()
    cert = Certificate(private_key=privk)
    cert.gen()
    certa = Certificate(cert=cert.cert)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature


def test_cert():
    """Test certificate content"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    cert = Certificate(private_key=privk)
    cert.gen()
    # save the certificate
    filepath = "/tmp/test/certs/www.example.com.crt"
    cert.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # test the content
    with open(filepath, "r") as pem_in:
        pemlines = pem_in.read()
    # begin at beginning
    assert pemlines.index("-----BEGIN CERTIFICATE-----") == 0
    # end at end
    len_end = len("-----END CERTIFICATE-----")
    assert pemlines.index("-----END CERTIFICATE-----") == len(pemlines) - len_end - 1
    assert pemlines.index("-----END CERTIFICATE-----") < len(pemlines)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_normal_cycle():
    """Test certificate generation, saving and loading : Normal cycle"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    cert = Certificate(private_key=privk)
    cert.gen()
    # save the certificate
    filepath = "/tmp/test/certs/www.example.com.crt"
    cert.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    certa = Certificate()
    certa.load(filepath)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_pem():
    """Test cycle with pem"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    cert = Certificate(private_key=privk)
    cert.gen()
    # save the certificate
    filepath = "/tmp/test/certs/www.example.com.pem"
    cert.save_pem(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    certa = Certificate()
    certa.load_pem(filepath)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_der():
    """Test cycle with der"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    cert = Certificate(private_key=privk)
    cert.gen()
    # save the certificate
    filepath = "/tmp/test/certs/www.example.com.der"
    cert.save_der(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    certa = Certificate()
    certa.load_der(filepath)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_self_signed():
    """Test cycle with self signed certificate"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    cert = Certificate(private_key=privk)
    cert.gen_self_signed()
    # save the certificate
    filepath = "/tmp/test/certs/www.example.com.crt"
    cert.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    certa = Certificate()
    certa.load(filepath)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature
    assert cert.cert.issuer == certa.cert.issuer
    assert cert.cert.subject == certa.cert.subject
    assert cert.cert.issuer == cert.cert.subject
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_additional_dns_names():
    """Test cycle with additional DNS names"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the certificate
    dns_names = ["example.com", "*.example.com"]
    cert = Certificate(private_key=privk)
    cert.gen(dns_names=dns_names)
    filepath = "/tmp/test/certs/www.example.com.crt"
    cert.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    certa = Certificate()
    certa.load(filepath)
    # test the certificates
    assert cert.cert.signature == certa.cert.signature
    test = 0
    for ext in cert.cert.extensions:
        if isinstance(ext.value, cryptx509.SubjectAlternativeName):
            test = 1
            assert "*.example.com" in ext.value.get_values_for_type(cryptx509.DNSName)
            assert "example.com" in ext.value.get_values_for_type(cryptx509.DNSName)
    # SubjectAlternativeName must be present
    if test == 0:
        assert False
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)
