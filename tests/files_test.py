# -*- coding: utf-8 -*-
""" Test suite : files.py
"""
import os
from pathlib import Path

from cryptopyutils import files


def test_filepath():
    """Test filepath generation : Standard case"""
    dir = "/tmp"
    host = "www.example.com"
    ext = "pem"
    fp = files.generate(host, dir, ext)
    assert str(fp) == "/tmp/www.example.com.pem"


def test_key():
    """Test filepath generation : key file"""
    dir = "/tmp"
    host = "www.example.com"
    fp = files.key(host, dir)
    assert str(fp) == "/tmp/private/www.example.com.key"


def test_crt():
    """Test filepath generation : crt file"""
    dir = "/tmp"
    host = "www.example.com"
    fp = files.crt(host, dir)
    assert str(fp) == "/tmp/certs/www.example.com.crt"


def test_csr():
    """Test filepath generation : csr file"""
    dir = "/tmp"
    host = "www.example.com"
    fp = files.csr(host, dir)
    assert str(fp) == "/tmp/csr/www.example.com.csr"


def test_pem():
    """Test filepath generation : pem file"""
    dir = "/tmp"
    host = "www.example.com"
    fp = files.pem(host, dir)
    assert str(fp) == "/tmp/private/www.example.com.pem"


def test_der():
    """Test filepath generation : der file"""
    dir = "/tmp"
    host = "www.example.com"
    fp = files.der(host, dir)
    assert str(fp) == "/tmp/private/www.example.com.der"


def test_pub():
    """Test filepath generation : pub file"""
    dir = "/temp"
    host = "www.example.com"
    fp = files.pub(host, out_dir=dir)
    assert str(fp) == "/temp/www.example.com.pub"


def test_file_exists():
    """Test file exists"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert (files.file_exists(filepath)) == False
    Path(filepath).touch()
    assert (files.file_exists(filepath)) == True
    os.remove(filepath)
    assert (files.file_exists(filepath)) == False


def test_cycle_read_write_text():
    """Test read write cycle of a text file"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert (files.file_exists(filepath)) == False
    data = "This is my text"
    files.write(filepath, data, istext=True)
    assert (files.file_exists(filepath)) == True
    # read the data
    data1 = files.read(filepath, istext=True)
    assert data == data1
    os.remove(filepath)
    assert (files.file_exists(filepath)) == False


def test_cycle_read_write_binary():
    """Test read write cycle of a binary file"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert (files.file_exists(filepath)) == False
    data = b"This is my text"
    files.write(filepath, data)
    assert (files.file_exists(filepath)) == True
    # read the data
    data1 = files.read(filepath)
    assert data == data1
    os.remove(filepath)
    assert (files.file_exists(filepath)) == False


def test_cycle_chmod():
    """Test cycle chmod"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert (files.file_exists(filepath)) == False
    Path(filepath).touch()
    assert (files.file_exists(filepath)) == True
    files.set_chmod(filepath, 0o700)
    ch = files.get_chmod(filepath)
    assert ch == 33216
    os.remove(filepath)
    assert (files.file_exists(filepath)) == False
