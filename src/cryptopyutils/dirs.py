# -*- coding: utf-8 -*-
"""dir.py - Directory manipulations
"""
import os
import shutil


def prep_dir_path(path):
    """Prepare a directory path by expanding and normalizing it

    Args:
        path (str): directory path

    """
    path1 = os.path.expanduser(path)
    path1 = os.path.expandvars(path1)
    path1 = os.path.normpath(path1)
    return path1


# Directory creation - removal


def mkdir(folder):
    """Creates the folder

    Args:
        dir(str): A directory path to create

    """
    dir1 = prep_dir_path(folder)
    if not os.path.exists(dir1):
        os.makedirs(dir1, exist_ok=True)


def rmdir(folder):
    """Removes the folder

    Args:
        dir(str): A directory path to remove

    """
    dir1 = prep_dir_path(folder)
    if os.path.exists(dir1):
        shutil.rmtree(dir1)
