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
"""Assymetric Encryption - Sign - Verify Example
"""
import os

from cryptopyutils import privatekey
from cryptopyutils import publickey


if __name__ == "__main__":
    print("\r\n")
    print("ASSYMETRIC ENCRYPTION - SIGN - VERIFY EXAMPLE\r\n")
    # choose your alg : RSA, DSA, ED448, ED25519, EC
    ALG = "RSA"
    # file path the the keys
    cdir = os.getcwd()

    # choose a text to sign and verify
    MESSAGE = b"This is the message to sign and verify 15338 #[%"
    print("\r\n")
    print("Text to sign and verify\r\n")
    print(MESSAGE)
    print("\r\n")

    # Sign the message with the private key
    private_key_filepath = os.path.join(cdir, "keys", ALG.lower() + "_priv.pem")
    privk = privatekey.PrivateKey(alg=ALG)
    privk.load(private_key_filepath)
    signature = privk.sign(MESSAGE)
    print("Signature\r\n")
    # The signature is returned in base64 format
    print(signature)
    print("\r\n")

    # Verify the message with the public key
    MESSAGE_TO_VERIFY = b"This is the message to sign and verify 15338 #[%"
    public_key_filepath = os.path.join(cdir, "keys", ALG.lower() + "_pub.pem")
    pubk = publickey.PublicKey()
    pubk.load(public_key_filepath)
    verif = pubk.verify(signature, MESSAGE_TO_VERIFY)

    # compare
    if verif:
        print("%s signature - verification cycle successful" % ALG)
    else:
        print("%s signature - verification cycle failure" % ALG)
    print("\r\n")
