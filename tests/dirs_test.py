# -*- coding: utf-8 -*-
""" Test suite : dirs.py
"""
import os

from cryptopyutils import dirs


def test_ssl_dir_created_removed():
    """Test tmp dir created then removed"""
    tmpdir = "/tmp/test/ssl"
    # test does not exist
    dirs.rmdir(tmpdir)
    assert not os.path.exists(tmpdir)
    # create
    dirs.mkdir(tmpdir)
    # test exists
    assert os.path.exists(tmpdir)
    # remove
    dirs.rmdir(tmpdir)
    # test does not exist
    assert not os.path.exists(tmpdir)


def test_ssl_dir_already_removed():
    """Test tmp dir already removed"""
    tmpdir = "/tmp/test/ssl"
    # remove
    dirs.rmdir(tmpdir)
    # test does no exist
    assert not os.path.exists(tmpdir)
    # remove
    dirs.rmdir(tmpdir)
    # test does no exist
    assert not os.path.exists(tmpdir)


def test_ssl_dir_already_created():
    """Test tmp dir already created"""
    tmpdir = "/tmp/test/ssl"
    # test does not exist
    assert not os.path.exists(tmpdir)
    # create
    dirs.mkdir(tmpdir)
    # create
    dirs.mkdir(tmpdir)
    # test exists
    assert os.path.exists(tmpdir)
