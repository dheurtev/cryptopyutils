# -*- coding: utf-8 -*-
""" Test suite : csr.py - x509 CSR
"""
import os

from cryptography import x509 as cryptx509
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.backends.openssl import x509
from cryptopyutils.csr import CSR
from cryptopyutils.privatekey import PrivateKey


def test_instanciation_new_csr():
    """Test CSR object instanciation with new certificate"""
    c = CSR()
    assert c.csr == None


def test_instanciation_private_csr():
    """Test CSR object instanciation with existing private key"""
    privk = PrivateKey()
    privk.gen()
    c = CSR(private_key=privk)
    c.gen("mychallenge")
    assert isinstance(c.csr, x509._CertificateSigningRequest)
    assert isinstance(c.private_key, PrivateKey)
    assert isinstance(c.private_key.key, rsa._RSAPrivateKey)


def test_instanciation_existing_csr():
    """Test CSR object instanciation with existing csr"""
    privk = PrivateKey()
    privk.gen()
    c = CSR(private_key=privk)
    c.gen("mychallenge")
    c1 = CSR(csr=c.csr)
    # test the CSRs
    assert c.csr.signature == c1.csr.signature


def test_normal_cycle():
    """Test csr generation, saving and loading : Normal cycle"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the csr
    csr = CSR(private_key=privk)
    csr.gen("mychallenge")
    # save the csr
    filepath = "/tmp/test/certs/www.example.com.csr"
    csr.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    csra = CSR()
    csra.load(filepath)
    # test the CSRs
    assert csr.csr.signature == csra.csr.signature
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_pem():
    """Test cycle with pem"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the CSR
    csr = CSR(private_key=privk)
    csr.gen("mychallenge")
    # save the CSR
    filepath = "/tmp/test/certs/www.example.com.csr"
    csr.save_pem(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    csra = CSR()
    csra.load_pem(filepath)
    # test the CSRs
    assert csr.csr.signature == csra.csr.signature
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_der():
    """Test cycle with der"""
    # generate private key
    privk = PrivateKey()
    privk.gen()
    # create the CSR
    csr = CSR(private_key=privk)
    csr.gen("mychallenge")
    # save the CSR
    filepath = "/tmp/test/certs/www.example.com.der"
    csr.save_der(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    csra = CSR()
    csra.load_der(filepath)
    # test the CSRs
    assert csr.csr.signature == csra.csr.signature
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
    csr = CSR(private_key=privk)
    csr.gen("mychallenge", dns_names=dns_names)
    filepath = "/tmp/test/certs/www.example.com.csr"
    csr.save(filepath)
    # test that the file exists
    assert os.path.exists(filepath)
    # load
    csra = CSR()
    csra.load(filepath)
    # test the certificates
    assert csr.csr.signature == csra.csr.signature
    test = 0
    for ext in csr.csr.extensions:
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
