# -*- coding: utf-8 -*-
"""Test privatekey.py
"""
import os

from cryptography.hazmat.backends.openssl import dsa
from cryptography.hazmat.backends.openssl import ec
from cryptography.hazmat.backends.openssl import ed25519
from cryptography.hazmat.backends.openssl import ed448
from cryptography.hazmat.backends.openssl import rsa
from cryptopyutils import files
from cryptopyutils.privatekey import PrivateKey


# Tests
def test_instanciation_new_key():
    """Test Private Key object instanciation with new key"""
    privk = PrivateKey()
    privk.gen()
    assert isinstance(privk.key, rsa._RSAPrivateKey)


def test_instanciation_existing_private_key():
    """Test Private Key object instanciation with existing RSAPrivateKey key"""
    privk = PrivateKey()
    privk.gen()
    pk1 = PrivateKey(key=privk.key)
    assert isinstance(pk1.key, rsa._RSAPrivateKey)


def test_gen_and_save():
    """Test private key generation and saving

    Reads the key content.
    Test with old style SSL
    """
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    # save the private key
    filepath = "/tmp/www.example.com.pem"
    # Remove if exists
    if os.path.exists(filepath):
        os.remove(filepath)
    # save
    status = privk.save(filepath, file_format="PKCS1", force=True)
    assert status
    # test that the file exists
    assert os.path.exists(filepath)
    # test that the chmod is correct
    stat = os.stat(filepath)
    assert stat.st_mode == 0o100600
    # test the content
    data = files.read(filepath)
    pemlines = str(data)
    # begin at beginning
    assert pemlines.index("-----BEGIN RSA PRIVATE KEY-----") == 2
    # end at end
    len_end = len("-----END RSA PRIVATE KEY-----")
    assert (
        pemlines.index("-----END RSA PRIVATE KEY-----") == len(pemlines) - len_end - 3
    )
    assert pemlines.index("-----END RSA PRIVATE KEY-----") < len(pemlines)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_gen_save_load():
    """Test private key generation, saving and loading : regular cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    # Remove if exists
    if os.path.exists(filepath):
        os.remove(filepath)
    # save
    status = privk.save(filepath)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath, encoding="PEM")
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_passphrase():
    """Test cycle with passphrase"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    passphrase = "this is a test"
    # Remove if exists
    if os.path.exists(filepath):
        os.remove(filepath)
    # save
    status = privk.save(filepath, passphrase=passphrase)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath, passphrase=passphrase)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_pem():
    """Test cycle with pem"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save_pem(filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load_pem(filepath)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_der():
    """Test cycle with der"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save_der(filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load_der(filepath)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_dsa():
    """Test private key generation, saving and loading : dsa cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen("DSA")
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save(filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # check it is a DSA key
    assert isinstance(privk.key, dsa._DSAPrivateKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_ed448():
    """Test private key generation, saving and loading : ed448 cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen("ED448")
    # check it is ED448 key
    assert isinstance(privk.key, ed448._Ed448PrivateKey)
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save(filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath)
    # test the keys with signatures
    message = b"test"
    assert privk.key.sign(message) == privka.key.sign(message)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_ed25519():
    """Test private key generation, saving and loading : ed25519 cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen(alg="ED25519")
    # check it is an ED25519 key
    assert isinstance(privk.key, ed25519._Ed25519PrivateKey)
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save(path=filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath)
    # test the keys with signatures
    message = b"test"
    assert privk.key.sign(message) == privka.key.sign(message)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_ec():
    """Test private key generation, saving and loading : standard ec cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen(alg="EC")
    # check it is an Elliptic Curve key
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save(path=filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_other_ec():
    """Test private key generation, saving and loading : other ec cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen(alg="EC", curve="SECP521R1")
    # check it is an Elliptic Curve key
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = privk.save(path=filepath, force=True)
    assert status
    # load the private key
    privka = PrivateKey()
    privka.load(filepath)
    # test the keys
    assert privk.key.private_numbers() == privka.key.private_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


# decrypt : tested in test_asym.py
# sign : tested in test_asym.py
