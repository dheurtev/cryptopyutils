# -*- coding: utf-8 -*-
"""Test sshkeypair.py - Test suite : SSH
"""
import os

from cryptography import x509
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptopyutils import files
from cryptopyutils.privatekey import PrivateKey
from cryptopyutils.publickey import PublicKey
from cryptopyutils.sshkeypair import SSHKeyPair


# Private Keys
def test_ssh_private_key():
    """Test SSH private key generation, saving and loading"""
    sshkp = SSHKeyPair()
    # generate the private key
    sshkp.gen_private_key()
    # save the private key
    filepath = "/tmp/test/private/www.example.com.pem"
    status = sshkp.save_private_key(filepath, force=True)
    assert status
    # load the private key
    sshkpa = SSHKeyPair()
    sshkpa.load_private_key(filepath)
    # test the keys
    assert isinstance(sshkpa.private_key, PrivateKey)
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_ssh_public_key():
    """Test SSH public key generation, saving and loading"""
    sshkp = SSHKeyPair()
    # generate the private key
    sshkp.gen_private_key()
    # generate the public key
    sshkp.gen_public_key()
    # save the public key
    filepath = "/tmp/test/private/www.example.com.pub"
    status = sshkp.save_public_key(filepath, force=True)
    assert status
    # load the public key
    sshkpa = SSHKeyPair()
    sshkpa.load_public_key(filepath)
    # test the keys
    assert (
        sshkp.public_key.key.public_numbers() == sshkpa.public_key.key.public_numbers()
    )
    # remove file
    os.remove(filepath)
    assert not os.path.exists(filepath)


def test_user_key_pair_rsa():
    """Test RSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("RSA", out_dir, force=True)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_user_key_pair_ed25519():
    """Test ed25519 key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("ED25519", out_dir, force=True)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_user_key_pair_dsa():
    """Test DSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("DSA", out_dir, force=True)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_user_key_pair_ecdsa():
    """Test ECDSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("ECDSA", out_dir, force=True)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_user_key_pair_rsa_comment():
    """Test RSA key pair generation with user_host data"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    comment = "root@example.com"
    status, fp = sshkp.key_pair("RSA", out_dir, comment=comment, force=True)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # test the content
    data = files.read(fp[1])
    pemlines = str(data)
    # check for the presence of user_host
    assert pemlines.index(comment) > 0
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_system_key_pair_rsa():
    """Test SSH system RSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("RSA", out_dir, force=True, is_user=False)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_system_key_pair_ed25519():
    """Test SSH system  ed25519 key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("ED25519", out_dir, force=True, is_user=False)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_system_key_pair_dsa():
    """Test SSH system  DSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("DSA", out_dir, force=True, is_user=False)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_system_key_pair_ecdsa():
    """Test SSH system  ECDSA key pair generation"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    status, fp = sshkp.key_pair("ECDSA", out_dir, force=True, is_user=False)
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False


def test_system_key_pair_rsa_comment():
    """Test SSH system RSA key pair generation with user_host data"""
    sshkp = SSHKeyPair()
    out_dir = "/tmp/.ssh"
    # generate and save the keypair
    comment = "root@example.com"
    status, fp = sshkp.key_pair(
        "RSA",
        out_dir,
        comment=comment,
        force=True,
        is_user=False,
    )
    assert status[1]
    # load the public key
    sshkp.load_private_key(fp[0])
    sshkp.load_public_key(fp[1])
    # test the content
    data = files.read(fp[1])
    pemlines = str(data)
    # check for the presence of user_host
    assert pemlines.index(comment) > 0
    # remove files
    os.remove(fp[0])
    assert os.path.exists(fp[0]) == False
    os.remove(fp[1])
    assert os.path.exists(fp[1]) == False
