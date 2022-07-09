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
"""sshkeypairgen.py - openSSH Key Pair Generator CLI
"""
import argparse
import os
import sys
from getpass import getpass

from cryptopyutils import dirs
from cryptopyutils import files
from cryptopyutils import publickey
from cryptopyutils import sshkeypair


def main():
    """
    Some equivalence with ssh-keygen (https://www.ssh.com/academy/ssh/keygenI)

    * -t rsa -b 4096
    * -t dsa
    * -t ed25519
    * -t ecdsa -b 521
    * -c comment (unique name identifying the key)

    By default, this tool generates id_[alg] and id_[alg].pub files with the --system
    option, it generates ssh_host_[alg]_key and ssh_host_[alg]_key.pub files.

    You need the --force option to overwrite existing files.

    """
    parser = argparse.ArgumentParser(
        description="openSSH KEY PAIR GENERATOR - basic ssh-keygen - user or system keys",
    )
    parser.add_argument(
        "-t",
        "--alg",
        choices=["rsa", "ed25519", "ecdsa", "dsa"],
        help="SSH key algorithm",
        default="rsa",
    )
    parser.add_argument(
        "-c",
        "--comment",
        help="comment, unique name key identifier, typically user@host",
        default=None,
    )
    parser.add_argument(
        "-b",
        "--bits",
        help="Bits (RSA key_size or EC curve length)",
        type=int,
        default="4096",
    )
    # Specific arguments
    parser.add_argument("-d", "--dir", help="Output directory", default="~/.ssh")
    parser.add_argument(
        "-s",
        "--system",
        help="Generates ssh host files",
        action="store_true",
    )
    parser.add_argument(
        "--force",
        help="Force existing file overwriting",
        action="store_true",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Password to encrypt the private key",
        action="store_true",
    )
    args = parser.parse_args()
    if args.password:
        passphrase = getpass()
    else:
        passphrase = None
    # create an instance of SSH object
    sshkp = sshkeypair.SSHKeyPair()
    args.alg = args.alg.lower()
    # algorithm and parameters supported
    if args.alg not in ["rsa", "ed25519", "ecdsa", "dsa"]:
        raise Exception("SSH algorithm not supported.")
    if args.alg == "rsa":
        if int(args.bits) not in [2048, 3072, 4096, 8192]:
            raise Exception("Incorrect number of bits must be 2048, 3072, 4096, 8192")
    if args.alg == "ecdsa":
        if int(args.bits) not in [256, 384, 521]:
            raise Exception("Incorrect number of bits must be 256, 384 or 521")
    # create the folder
    dirs.mkdir(args.dir)
    # generate the keypair and obtain the filepath
    if args.system:
        status, path = sshkp.key_pair(
            args.alg.upper(),
            args.dir,
            key_size=args.bits,
            curve_length=args.bits,
            comment=args.comment,
            force=args.force,
            passphrase=passphrase,
            is_user=False,
        )
    else:
        status, path = sshkp.key_pair(
            args.alg.upper(),
            args.dir,
            key_size=args.bits,
            curve_length=args.bits,
            comment=args.comment,
            force=args.force,
            passphrase=passphrase,
            is_user=True,
        )

    # exit if error
    if not status[0]:
        print(
            "ERROR : Private key file %s could not be saved. You probably need the --force option to overwrite existing files."
            % (path[0]),
        )
        sys.exit(1)
    if not status[1]:
        print(
            'ERROR : Public key file %s could not be saved". You probably need the --force option to overwrite existing files.'
            % (path[1]),
        )
        sys.exit(1)

    # read the private key and print it on screen
    fp_private_key = path[0]
    fp_public_key = path[1]
    data_private_key = files.read(fp_private_key)
    # output result
    print("\r\n%s - PRIVATE KEY" % args.alg)
    print("\r\n%s\r\n" % fp_private_key)
    print(str(data_private_key.decode("UTF-8")))
    # read the public key and print it on screen
    data_public_key = files.read(fp_public_key)
    print("\r\n%s - PUBLIC KEY" % args.alg)
    print("\r\n%s\r\n" % fp_public_key)
    print(data_public_key.decode())
    print("\r\nFINGERPRINTS\r\n")
    print("%s\r" % (sshkp.hash_fingerprint(fp_public_key, "MD5")))
    print("%s\r" % (sshkp.hash_fingerprint(fp_public_key, "SHA-256")))
    print("%s\r" % (sshkp.hash_fingerprint(fp_public_key, "SHA-512")))
    print("\r\n")


if __name__ == "__main__":
    main()
