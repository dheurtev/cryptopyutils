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
"""Password Encryption CLI
"""
import argparse
import base64
import sys
from getpass import getpass

from cryptopyutils.password import Password


def main():
    """Password encryption

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description="PASSWORD ENCRYPTION CLI")
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
    args = parser.parse_args()
    if not args.password and args.apipass is None:
        print(
            "use the -p option to type the password or the -a option with the password\
            (VERY INSECURE can be recorded in various places)",
        )
        sys.exit(1)
    if args.password:
        password = getpass()
        # Derive / Encrypt the password and obtain the key and the salt
        pwd = Password()
        key, salt = pwd.derive(password)
        print("Salt (base64) : %s " % (base64.b64encode(salt).decode("utf8")))
        print("Key (base64) : %s " % (base64.b64encode(key).decode("utf8")))
    if args.apipass:
        # Derive / Encrypt the password and obtain the key and the salt
        pwd = Password()
        key, salt = pwd.derive(args.apipass)
        salt = base64.b64encode(salt).decode("utf8")
        key = base64.b64encode(key).decode("utf8")
        print("PWDENC %s %s" % (key, salt))


if __name__ == "__main__":
    main()
