#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright 2022 David HEURTEVENT <david@heurtevent.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Password Verification CLI
"""
import argparse
import base64
import binascii
import sys
from getpass import getpass

from cryptopyutils.password import Password


def main():
    """Password Verification

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description="PASSWORD VERIFICATION CLI")
    parser.add_argument(
        "-p",
        "--password",
        help="Password to encrypt",
        action="store_true",
    )
    parser.add_argument(
        "-a",
        "--apipass",
        help="Password to encrypt - INSECURE",
        type=str,
    )
    parser.add_argument("-s", "--salt", help="Salt (Base64)", type=str)
    parser.add_argument("-k", "--key", help="Key (Base64)", type=str)
    args = parser.parse_args()
    if not args.password and args.apipass is None:
        print(
            "use the -p option to type the password or the -a option with the password\
            (VERY INSECURE can be recorded in various places)",
        )
        sys.exit(1)
    if args.password:
        password = getpass()
    if args.apipass:
        password = args.apipass
    # instance of the password object
    pwd = Password()
    # verification - key and salt must be in base64 format
    try:
        saltb = base64.b64decode(args.salt.encode("utf8"))
        keyb = base64.b64decode(args.key.encode("utf8"))
    except binascii.Error:
        print("The salt and key must be in base64 format")
        sys.exit(1)
    verif = pwd.verify(password, keyb, saltb)
    if args.password:
        print("Password verification test result is %s" % verif)
    if args.apipass:
        return print("PWDVERIF:%s" % verif)


if __name__ == "__main__":
    main()
