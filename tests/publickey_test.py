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
from cryptopyutils.publickey import PublicKey


def test_instanciation_new_key():
    """Test Public Key object instanciation with new key"""
    pubk = PublicKey()
    assert pubk.key is None


def test_instanciation_private_key():
    """Test Public Key object instanciation with existing private key"""
    privk = PrivateKey()
    privk.gen("RSA")
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    assert isinstance(pubk1.key, rsa._RSAPublicKey)
    assert isinstance(pubk1.private_key.key, rsa._RSAPrivateKey)


def test_instanciation_existing_public_key():
    """Test Public Key object instanciation with existing public key"""
    privk = PrivateKey()
    privk.gen("RSA")
    pubk = PublicKey(private_key=privk)
    pubk.gen("RSA")
    pubk1 = PublicKey(key=pubk.key)
    assert isinstance(pubk1.key, rsa._RSAPublicKey)


def test_gen_and_save_():
    """Test public key generation and saving

    Reads the key content.
    Test with old style SSL
    """
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    pubk = PublicKey(private_key=privk)
    pubk.gen()
    # save the public key
    filepath = "/tmp/www.example.com.pem"
    status = pubk.save(path=filepath, file_mode=0o700, force=True)
    assert status
    # test that the file exists
    assert os.path.exists(filepath)

    # test that the chmod is correct
    stat = os.stat(filepath)
    assert stat.st_mode == 0o100700

    # test the content
    data = files.read(filepath)
    pemlines = str(data)
    # begin at beginning
    assert pemlines.index("-----BEGIN PUBLIC KEY-----") == 2
    # end at end
    len_end = len("-----END PUBLIC KEY-----")
    assert pemlines.index("-----END PUBLIC KEY-----") == len(pemlines) - len_end - 3
    assert pemlines.index("-----END PUBLIC KEY-----") < len(pemlines)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_gen_save_load():
    """Test public key generation, saving and loading : regular cycle"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    pubk = PublicKey(private_key=privk)
    pubk.gen()
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert pubk.key.public_numbers() == pubka.key.public_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_pem():
    """Test cycle with pem"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    pubk = PublicKey(private_key=privk)
    pubk.gen()
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save_pem(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load_pem(filepath)
    # test the keys
    assert pubk.key.public_numbers() == pubka.key.public_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_cycle_der():
    """Test cycle with der"""
    # generate the private key
    privk = PrivateKey()
    privk.gen()
    pubk = PublicKey(private_key=privk)
    pubk.gen()
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save_der(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load_der(filepath)
    # test the keys
    assert pubk.key.public_numbers() == pubka.key.public_numbers()
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_dsa_cycle():
    """Test public key generation, saving and loading : dsa cycle"""
    # generate the private key
    alg = "DSA"
    privk = PrivateKey()
    privk.gen(alg)
    pubk = PublicKey(private_key=privk)
    pubk.gen(alg)
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert pubk.key.public_numbers() == pubka.key.public_numbers()
    assert isinstance(pubka.key, dsa._DSAPublicKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_ed448_cycle():
    """Test public key generation, saving and loading : ed448 cycle"""
    # generate the private key
    alg = "ED448"
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ed448._Ed448PrivateKey)
    pubk = PublicKey(private_key=privk)
    pubk.gen(alg)
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert isinstance(pubka.key, ed448._Ed448PublicKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_ed25519_cycle():
    """Test public key generation, saving and loading : ed25519 cycle"""
    # generate the private key
    alg = "ED25519"
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ed25519._Ed25519PrivateKey)
    pubk = PublicKey(private_key=privk)
    pubk.gen(alg)
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert isinstance(pubka.key, ed25519._Ed25519PublicKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_ec_cycle():
    """Test public key generation, saving and loading : standard ec cycle"""
    # generate the private key
    alg = "EC"
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    pubk = PublicKey(private_key=privk)
    pubk.gen(alg)
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert isinstance(pubka.key, ec._EllipticCurvePublicKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_other_ec_cycle():
    """Test public key generation, saving and loading : standard ec cycle"""
    alg = "EC"
    # generate the private key
    privk = PrivateKey()
    privk.gen(alg, curve="SECP521R1")
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    pubk = PublicKey(private_key=privk)
    pubk.gen(alg)
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = pubk.save(filepath, force=True)
    assert status
    # load the public key
    pubka = PublicKey()
    pubka.load(filepath)
    # test the keys
    assert isinstance(pubka.key, ec._EllipticCurvePublicKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


# encrypt : tested in test_asym.py
# verify : tested in test_asym.py
