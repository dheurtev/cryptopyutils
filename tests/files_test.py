# -*- coding: utf-8 -*-
""" Test suite : files.py
"""
import os
from pathlib import Path

from cryptopyutils import files


def test_filepath():
    """Test filepath generation : Standard case"""
    dir_path = "/tmp"
    host = "www.example.com"
    ext = "pem"
    file_path = files.generate(host, dir_path, ext)
    assert str(file_path) == "/tmp/www.example.com.pem"


def test_key():
    """Test filepath generation : key file"""
    dir_path = "/tmp"
    host = "www.example.com"
    file_path = files.key(host, dir_path)
    assert str(file_path) == "/tmp/private/www.example.com.key"


def test_crt():
    """Test filepath generation : crt file"""
    dir_path = "/tmp"
    host = "www.example.com"
    file_path = files.crt(host, dir_path)
    assert str(file_path) == "/tmp/certs/www.example.com.crt"


def test_csr():
    """Test filepath generation : csr file"""
    dir_path = "/tmp"
    host = "www.example.com"
    file_path = files.csr(host, dir_path)
    assert str(file_path) == "/tmp/csr/www.example.com.csr"


def test_pem():
    """Test filepath generation : pem file"""
    dir_path = "/tmp"
    host = "www.example.com"
    file_path = files.pem(host, dir_path)
    assert str(file_path) == "/tmp/private/www.example.com.pem"


def test_der():
    """Test filepath generation : der file"""
    dir_path = "/tmp"
    host = "www.example.com"
    file_path = files.der(host, dir_path)
    assert str(file_path) == "/tmp/private/www.example.com.der"


def test_pub():
    """Test filepath generation : pub file"""
    dir_path = "/temp"
    host = "www.example.com"
    file_path = files.pub(host, out_dir=dir_path)
    assert str(file_path) == "/temp/www.example.com.pub"


def test_file_exists():
    """Test file exists"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert not files.file_exists(filepath)
    Path(filepath).touch()
    assert files.file_exists(filepath)
    os.remove(filepath)
    assert not files.file_exists(filepath)


def test_cycle_read_write_text():
    """Test read write cycle of a text file"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert not files.file_exists(filepath)
    data = "This is my text"
    files.write(filepath, data, istext=True)
    assert files.file_exists(filepath)
    # read the data
    data1 = files.read(filepath, istext=True)
    assert data == data1
    os.remove(filepath)
    assert not files.file_exists(filepath)


def test_cycle_read_write_binary():
    """Test read write cycle of a binary file"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert not files.file_exists(filepath)
    data = b"This is my text"
    files.write(filepath, data)
    assert files.file_exists(filepath)
    # read the data
    data1 = files.read(filepath)
    assert data == data1
    os.remove(filepath)
    assert not files.file_exists(filepath)


def test_cycle_chmod():
    """Test cycle chmod"""
    filepath = "/tmp/tmpfile12395698744"
    if os.path.exists(filepath):
        os.remove(filepath)
    assert not files.file_exists(filepath)
    Path(filepath).touch()
    assert files.file_exists(filepath)
    files.set_chmod(filepath, 0o700)
    chmode = files.get_chmod(filepath)
    assert chmode == 33216
    os.remove(filepath)
    assert not files.file_exists(filepath)
