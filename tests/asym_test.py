# -*- coding: utf-8 -*-
"""Test Asymmetric Encryption Decryption - Signature verification
"""
from cryptography.hazmat.backends.openssl import dsa
from cryptography.hazmat.backends.openssl import ec
from cryptography.hazmat.backends.openssl import ed25519
from cryptography.hazmat.backends.openssl import ed448
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives import hashes
from cryptopyutils.privatekey import PrivateKey
from cryptopyutils.publickey import PublicKey


def test_encryption_decryption_cycle():
    """Test encryption and decryption cycle using an
    Asymmetric RSA private key / public key pair"""
    # create the private key
    privk = PrivateKey()
    privk.gen()
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the message
    plaintext = b"This is the message to cipher 15338 #[%"
    # encrypt with the public key
    ciphertext = pubk1.encrypt(plaintext)
    # decrypt with the private key
    plaintext1 = privk.decrypt(ciphertext)
    # compare
    assert len(plaintext) == len(plaintext1)
    assert plaintext == plaintext1


def test_str_encryption_decryption_cycle():
    """Test encryption and decryption cycle using an
    Asymmetric RSA private key / public key pair
    for a text
    """
    # create the private key
    privk = PrivateKey()
    privk.gen()
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the message
    plaintext = "This is the message to cipher 15338 #[%"
    # encrypt with the public key
    ciphertext = pubk1.encrypt(plaintext)
    # decrypt with the private key
    plaintext1 = privk.decrypt(ciphertext, text=True)
    # compare
    assert len(plaintext) == len(plaintext1)
    assert plaintext == plaintext1


def test_sign_verify_cycle():
    """Test sign and verify cycle using an Asymmetric RSA
    private key / public key pair"""
    # create the private key
    privk = PrivateKey()
    privk.gen()
    assert isinstance(privk.key, rsa._RSAPrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_cycle_incorrect_sig():
    """Test sign and verify cycle using an Asymmetric RSA
    private key / public key pair
    with an incorrect signature
    """
    # create the private key
    privk = PrivateKey()
    privk.gen()
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    message1 = b"This is the message to cipher 15338 #[% wrong"
    verif = pubk1.verify(signature, message1)
    # compare
    assert not verif


def test_sign_verify_cycle_dsa():
    """Test sign and verify cycle using an Asymmetric DSA
    private key / public key pair"""
    alg = "DSA"
    # create the private key
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, dsa._DSAPrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen(alg)
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_cycle_ed448():
    """Test sign and verify cycle using an Asymmetric ED448
    private key / public key pair"""
    alg = "ED448"
    # create the private key
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ed448._Ed448PrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen(alg)
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_cycle_ed25519():
    """Test sign and verify cycle using an Asymmetric ED25519
    private key / public key pair"""
    alg = "ED25519"
    # create the private key
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ed25519._Ed25519PrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen(alg)
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_cycle_ec():
    """Test sign and verify cycle using an Asymmetric Elliptic Curve
    private key / public key pair"""
    alg = "EC"
    # create the private key
    privk = PrivateKey()
    privk.gen(alg)
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen(alg)
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_other_cycle_ec():
    """Test sign and verify cycle using an Asymmetric a non standard Elliptic Curve
    private key / public key pair"""
    alg = "EC"
    # create the private key
    privk = PrivateKey()
    privk.gen(alg, curve="SECP521R1")
    assert isinstance(privk.key, ec._EllipticCurvePrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the message
    message = b"This is the message to cipher 15338 #[%"
    # sign with the private key
    signature = privk.sign(message)
    # decrypt with the private key
    verif = pubk1.verify(signature, message)
    # compare
    assert verif


def test_sign_verify_pre_hashed_cycle():
    """Test sign and verify cycle using an Asymmetric RSA private key / public key pair
    with pre_hashed values
    """
    # create the private key
    privk = PrivateKey()
    privk.gen()
    assert isinstance(privk.key, rsa._RSAPrivateKey)
    # create the public key
    pubk1 = PublicKey(private_key=privk)
    pubk1.gen()
    # set the messages and compute the digest
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(b"abc")
    hasher.update(b"123")
    digest = hasher.finalize()
    # sign with the private key
    signature = privk.sign(digest, pre_hashed=True)
    # decrypt with the private key
    verif = pubk1.verify(signature, digest, pre_hashed=True)
    # compare
    assert verif
