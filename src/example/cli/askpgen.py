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
"""Asymmetric Encryption Key Pair Generator CLI - PEM format
"""
import argparse
import os
from getpass import getpass

from cryptopyutils import dirs
from cryptopyutils import files
from cryptopyutils import privatekey
from cryptopyutils import publickey
from cryptopyutils import utils


def main():
    """Asymmetric encryption key pair generator - PEM format"""
    parser = argparse.ArgumentParser(
        description="ASYMMETRIC ENCRYPTION KEY PAIR GENERATOR - PEM FORMAT",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Key name (usually your FQDN www.example.com)",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-a",
        "--alg",
        choices=["rsa", "ed25519", "ed448", "ecdsa", "dsa"],
        help="Key algorithm",
        default="rsa",
    )
    parser.add_argument("-d", "--dir", help="Output directory", default="/tmp/keys")
    parser.add_argument(
        "-b",
        "--bits",
        help="Bits (RSA or DSA key size)",
        type=int,
        default="4096",
    )
    parser.add_argument(
        "-c",
        "--curve",
        help="Elliptic Curve name",
        type=str,
        default="SECP384R1",
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
    # create directories
    dirs.mkdir(args.dir)
    priv_path = os.path.join(args.dir, args.name + ".pem")
    pub_path = os.path.join(args.dir, args.name + ".pub")
    # algorithm and parameters supported
    if args.alg == "rsa":
        if int(args.bits) not in [2048, 3072, 4096, 8192]:
            raise Exception("Incorrect number of bits must be 2048, 3072, 4096, 8192")
        ALG = "RSA"
        # generate the private key
        private_key = privatekey.PrivateKey(alg=ALG)
        private_key.gen_rsa(key_size=args.bits)
        # save the private key
        status_pk = private_key.save(priv_path, force=args.force, passphrase=passphrase)
    elif args.alg == "ecdsa":
        if utils.ellipctic_curve(args.curve) is None:
            raise Exception("Incorrect curve name. Try SECP384R1.")
        ALG = "EC"
        args.bits = args.curve.lower()
        # generate the private key
        private_key = privatekey.PrivateKey(alg=ALG)
        private_key.gen_ec(curve=args.curve)
        # save the private key
        status_pk = private_key.save(priv_path, force=args.force, passphrase=passphrase)
    elif args.alg == "dsa":
        if int(args.bits) not in [1024, 2048, 3072, 4096, 8192]:
            raise Exception(
                "Incorrect number of bits must be 1024, 2048, 3072, 4096, 8192",
            )
        ALG = "DSA"
        # generate the private key
        private_key = privatekey.PrivateKey(alg=ALG)
        private_key.gen_dsa(key_size=args.bits)
        # save the private key
        status_pk = private_key.save(priv_path, force=args.force, passphrase=passphrase)
    elif args.alg == "ed448":
        args.bits = ""
        ALG = "ED448"
        # generate the private key
        private_key = privatekey.PrivateKey(alg=ALG)
        private_key.gen_ed448()
        # save the private key
        status_pk = private_key.save(priv_path, force=args.force, passphrase=passphrase)
    elif args.alg == "ed25519":
        args.bits = ""
        ALG = "ED25519"
        # generate the private key
        private_key = privatekey.PrivateKey(alg=ALG)
        private_key.gen_ed25519()
        # save the private key
        status_pk = private_key.save(priv_path, force=args.force, passphrase=passphrase)
    else:
        raise Exception("Algorithm not supported.")

    # generate and save the public key if ok for private key
    if status_pk:
        public_key = publickey.PublicKey(private_key=private_key)
        public_key.gen(alg=ALG)
        status_pubk = public_key.save(pub_path, force=args.force)

    # read the private key and print it on screen
    print("\r\n%s %s - PRIVATE KEY  :\r\n" % (args.alg, args.bits))
    if status_pk:
        print("\r\n%s\r\n" % priv_path)
        data_pk = files.read(priv_path)
        print(str(data_pk.decode("UTF-8")))
    else:
        print(
            "Error in generating and saving the private key. Maybe you need to overwrite existing files with the --force option",
        )

    # read the public key and print it on screen
    print("\r\n%s %s - PUBLIC KEY :\r\n" % (args.alg, args.bits))
    if status_pk and status_pubk:
        print("\r\n%s\r\n" % pub_path)
        data_pubk = files.read(pub_path)
        print(str(data_pubk.decode("UTF-8")))
        print("\r\n")
    else:
        print(
            "Error in generating and saving the public key. Maybe you need to overwrite existing files with the --force option",
        )


if __name__ == "__main__":
    main()
