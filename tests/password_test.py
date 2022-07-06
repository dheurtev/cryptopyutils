# -*- coding: utf-8 -*-
"""Test password.py
"""
from cryptopyutils.password import Password


def test_true_password():
    """Test a correct password"""
    pwd = Password()
    passw = "This is my password"
    # derive
    key, salt = pwd.derive(passw)
    # verify
    verif = pwd.verify(passw, key, salt)
    assert verif


def test_incorrect_password():
    """Test a correct password"""
    pwd = Password()
    passw = "This is my password"
    # derive
    key, salt = pwd.derive(passw)
    # verify
    passw1 = "This is my fake password"
    verif = pwd.verify(passw1, key, salt)
    assert not verif
