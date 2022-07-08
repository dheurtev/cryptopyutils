# -*- coding: utf-8 -*-
"""files.py - Files manipulation and filepaths generation
"""
import os
from os.path import expanduser

from . import dirs

HOME = expanduser("~")


# Files Manipulation


def get_chmod(path):
    """Returns the mode of a file using chmod

    Args:
        path (str): the file path.

    Returns:
        byte: the file mode (st_mode) or None if the file path does not exist.

    """
    path1 = dirs.prep_dir_path(path)
    if os.path.exists(path1):
        status = os.stat(path1)
        return status.st_mode
    else:
        return None


def set_chmod(path, mode):
    """Set the chmod of a file

    Args:
        path (str): the file path.
        mode(byte): the file mode.

    Returns:
        byte: the file mode (st_mode) as read back or None if the file path
            does not exist.

    """
    path1 = dirs.prep_dir_path(path)
    if os.path.exists(path1):
        os.chmod(path1, mode)
        return get_chmod(path1)
    else:
        return None


def write(path, data, encoding=None, istext=False):
    """Write the data (binary or text) to the file

    Args:
        path (str): the file path.
        data (bytes): the content to write to the file.
        encoding(str, optional): the encoding. Defaults to None.
        istext (bool): indicates if it should be written as text.

    Returns:
        bool: True if performed successfully.

    """
    path1 = dirs.prep_dir_path(path)
    # create directories
    os.makedirs(os.path.dirname(path1), exist_ok=True)

    # write to file
    if istext:
        mode = "w"
    else:
        mode = "wb"
    with open(path1, mode, encoding=encoding) as out:
        out.write(data)
        out.close()


def read(path, encoding=None, istext=False):
    """Reads the data (binary of text) from the file

    Args:
        path (str): the file path
        encoding(str, optional): the encoding. Defaults to None.
        istext (bool): indicate if it should be written as text.

    Returns:
        str: the content of the file.

    """
    path1 = dirs.prep_dir_path(path)
    if istext:
        mode = "r"
    else:
        mode = "rb"
    with open(path1, mode, encoding=encoding) as data_in:
        data = data_in.read()
    return data


def file_exists(path):
    """Determine if the file exists

    Args:
        path (str): the filepath.

    Returns:
        bool: True if exists, else False.

    """
    path1 = dirs.prep_dir_path(path)
    if os.path.exists(path1):
        return True
    else:
        return False


# Filepath generation


def generate(host_dns, out_dir=None, ext="pem"):
    """Generate the filepath for a private key, public key, certificate, csr ...

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.
        ext (str, optional): The file extension.
            Typically `crt` for certificates, `csr` for CSR.
            Defaults to `pem`.

    Returns:
        str: The filepath.

    """
    dir1 = dirs.prep_dir_path(out_dir)
    return os.path.join(dir1, host_dns + "." + ext)


def key(host_dns, out_dir=None):
    """Generate the filepath for a private key

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "private"), "key")


def csr(host_dns, out_dir=None):
    """Generate the filepath for a CSR

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "csr"), "csr")


def crt(host_dns, out_dir=None):
    """Generate the filepath for a Certificate with .crt extension

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "certs"), "crt")


def cer(host_dns, out_dir=None):
    """Generate the filepath for a Certificate with .cer extension

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "certs"), "cer")


def pem(host_dns, out_dir=None):
    """Generate the filepath for a PEM private key file

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "private"), "pem")


def der(host_dns, out_dir=None):
    """Generate the filepath for a DER private key file

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, os.path.join(out_dir, "private"), "der")


def pub(host_dns, out_dir=None):
    """Generate the filepath for a SSH public key file

    Args:
        host_dns (str): The FDQN of the host.
        out_dir (str, optional): The directory.
            Defaults to None.

    Returns:
        str: The filepath.

    """
    return generate(host_dns, out_dir, "pub")
