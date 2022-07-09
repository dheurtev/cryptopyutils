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
"""RSA Encryption / Decryption Example
"""
import os

from cryptopyutils import privatekey
from cryptopyutils import publickey


if __name__ == "__main__":
    print("\r\n")
    print("RSA ENCRYPTION - DECRYPTION EXAMPLE\r\n")

    # file path to the keys
    cdir = os.getcwd()

    # choose a text to encrypt
    PLAINTEXT = b"This is the message to cipher 15338 #[%"
    print("\r\n")
    print("Text to encrypt\r\n")
    print(PLAINTEXT)
    print("\r\n")

    # encrypt with the public key

    # load the public key
    public_key_filepath = os.path.join(cdir, "keys", "rsa_pub.pem")
    pubk = publickey.PublicKey()
    pubk.load(public_key_filepath)
    # encrypt with the public key
    ciphertext = pubk.encrypt(PLAINTEXT)
    print("Encrypted text\r\n")
    # The cipheredtext is returned in base64 format
    print(ciphertext)
    print("\r\n")

    # decrypt with the private key

    # load the private key
    private_key_filepath = os.path.join(cdir, "keys", "rsa_priv.pem")
    privk = privatekey.PrivateKey()
    privk.load(private_key_filepath)
    plaintext1 = privk.decrypt(ciphertext)
    print("Decrypted text\r\n")
    print(plaintext1)
    print("\r\n")

    # compare
    if PLAINTEXT == plaintext1:
        print("RSA Encryption / Decryption cycle successful")
    else:
        print("RSA Encryption / Decryption cycle failure")
    print("\r\n")
