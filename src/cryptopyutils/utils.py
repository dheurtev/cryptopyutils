# -*- coding: utf-8 -*-
"""utils.py - Utils """
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding


def compare_bytes(left, right):
    """Compares two series of bytes

    Uses constant times to prevent timing attacks.

    Args:
        left (bytes): left series of bytes.
        right (bytes): right series of bytes.

    Returns:
        bool: True if equal, False if not equal.

    """
    return constant_time.bytes_eq(left, right)


def private_alg(passphrase):
    """Private algorithm

    Args:
        passphrase (str): Key password / passphrase string.

    """
    if passphrase is None:
        # no passphrase
        alg = serialization.NoEncryption()
    else:
        # case with passphrase
        pwd = bytes(passphrase, encoding="utf8")
        alg = serialization.BestAvailableEncryption(pwd)
    return alg


def convert_passphrase(passphrase):
    """Converts the passphrase if needed

    Args:
        passphrase (str): Key password / passphrase string.

    Returns:
        None or bytes.

    """
    if passphrase is None:
        return None
    else:
        return bytes(passphrase, encoding="utf8")


def file_encoding(encoding=None):
    """Returns the file encoding

    Args:
        encoding (str, optional): Encoding PEM, DER or OpenSSH
            Not supported by cryptopyutils: RAW, X962, SMIME.
            Defaults to None.
            https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

    Returns:
        Encoding: A serialization Encoding object.

    """
    enc = {
        "PEM": serialization.Encoding.PEM,
        "DER": serialization.Encoding.DER,
        "OpenSSH": serialization.Encoding.OpenSSH,
        # "X962": serialization.Encoding.X962,
        # "SMIME": serialization.Encoding.SMIME,
        # "RAW": serialization.Encoding.Raw,
    }
    if encoding in enc.keys():
        return enc[encoding]
    else:
        return None


def private_format(fmt=None):
    """Returns the private key format

    Args:
        fmt (str, optional): Format : PKCS8, PKCS1 or OpenSSH.
            Not supported by cryptopyutils: RAW
            Defaults to None.
            https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

    Returns:
        PrivateFormat: A serialization PrivateFormat object.

    """
    formats = {
        "PKCS1": serialization.PrivateFormat.TraditionalOpenSSL,
        "PKCS8": serialization.PrivateFormat.PKCS8,
        "OpenSSH": serialization.PrivateFormat.OpenSSH,
        # "RAW": serialization.PrivateFormat.Raw,
    }
    if fmt in formats.keys():
        return formats[fmt]
    else:
        return None


def public_format(fmt=None):
    """Returns the public key format

    Args:
        fmt (str, optional): Format : SubjectPublicKeyInfo, PKCS1 or OpenSSH.
            Not supported by cryptopyutils: RAW, CompressedPoint, UncompressedPoint
            Defaults to None.

    Returns:
        PublicFormat: A serialization PublicFormat object.
    """
    formats = {
        "PKCS1": serialization.PublicFormat.PKCS1,
        "SubjectPublicKeyInfo": serialization.PublicFormat.SubjectPublicKeyInfo,
        "OpenSSH": serialization.PublicFormat.OpenSSH,
        # "CompressedPoint": serialization.PublicFormat.CompressedPoint,
        # "UncompressedPoint": serialization.PublicFormat.UncompressedPoint,
        # "RAW": serialization.PublicFormat.Raw,
    }
    if fmt in formats.keys():
        return formats[fmt]
    else:
        return None


def ellipctic_curve(name=None):
    """Returns the Elliptic Curve object based on its name

    Args:
        name (str, optional): The name of the elliptic curve.
        Defaults to None.

    Returns:
        EllipticCurve: An instance of the Elliptic Curve.

    """
    elipc = {
        "SECP192R1": ec.SECP384R1(),
        "SECP224R1": ec.SECP224R1(),
        "SECP256K1": ec.SECP256K1(),
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1(),
        "BRAINPOOLP256R1": ec.BrainpoolP256R1(),
        "BRAINPOOLP384R1": ec.BrainpoolP384R1(),
        "BRAINPOOLP512R1": ec.BrainpoolP512R1(),
        "SECT163K1": ec.SECT163K1(),
        "SECT163R2": ec.SECT163R2(),
        "SECT233K1": ec.SECT233K1(),
        "SECT233R1": ec.SECT233R1(),
        "SECT283K1": ec.SECT283K1(),
        "SECT283R1": ec.SECT283R1(),
        "SECT409K1": ec.SECT409K1(),
        "SECT409R1": ec.SECT409R1(),
        "SECT571K1": ec.SECT571K1(),
        "SECT571R1": ec.SECT571R1(),
    }
    if name in elipc.keys():
        return elipc[name]
    else:
        return None


def hash_algorithm(alg=None):
    """Returns the HashAlgorithm object for a given algorithm

    https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes

    Args:
        alg (str): The hashing algorithm.
            Defaults to None.

    Returns:
        HashAlgorithm: An instance of HashAlgorithm.

    """
    hashalgs = {
        "SHA-224": hashes.SHA224(),
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
        "SHA-512-224": hashes.SHA512_224(),
        "SHA-512-256": hashes.SHA512_256(),
        "BLAKE2b": hashes.BLAKE2b(64),
        "BLAKE2s": hashes.BLAKE2s(32),
        "SHA3-224": hashes.SHA3_224(),
        "SHA3-256": hashes.SHA3_256(),
        "SHA3-384": hashes.SHA3_384(),
        "SHA3-512": hashes.SHA3_512(),
        "SHAKE128": hashes.SHAKE128(8),
        "SHAKE256": hashes.SHAKE256(16),
        "SHA-1": hashes.SHA1(),
        "MD5": hashes.MD5(),
        # 'SM3': hashes.SM3(),
    }
    if alg in hashalgs.keys():
        return hashalgs[alg]
    else:
        return None


def oaep_mgf1_padding(hash_alg=None):
    """RSA OAEP MGF1 Padding

    Args:
        hash_alg (str, optional): the name of the hash algorithm.
            Defaults to None.

    """
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hash_algorithm(hash_alg)),
        algorithm=hash_algorithm(hash_alg),
        label=None,
    )
    return pad


def pss_mgf1_padding(hash_alg=None):
    """Signature PSS MGF1 Padding

    Args:
        hash_alg (str, optional): the name of the hash algorithm.
            Defaults to None.

    """
    pad = padding.PSS(
        mgf=padding.MGF1(hash_algorithm(hash_alg)),
        salt_length=padding.PSS.MAX_LENGTH,
    )
    return pad
