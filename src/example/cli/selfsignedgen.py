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
"""Self-Signed x509 PEM certificate generator CLI
"""
import argparse
import sys

import yaml
from cryptopyutils import cert
from cryptopyutils import dirs
from cryptopyutils import files
from cryptopyutils import privatekey


def main():
    """SELF-SIGNED x509 PEM CERTIFICATE GENERATOR"""
    parser = argparse.ArgumentParser(
        description="SELF-SIGNED x509 PEM CERTIFICATE GENERATOR",
    )
    parser.add_argument(
        "-f",
        "--privatekeyfile",
        help="Path to the private key file",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Key name (usually your FQDN www.example.com)",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-y",
        "--config",
        help="path to the YAML config file",
        type=str,
        required=True,
    )
    parser.add_argument("-D", "--dir", help="Output directory", type=str, required=True)
    parser.add_argument("--force", help="Force file overwriting", action="store_true")
    args = parser.parse_args()
    # future Certificate filepath
    fp_crt = files.crt(args.name, args.dir)
    # load the yaml configuration file
    with open(args.config, "r") as file:
        configdata = yaml.safe_load(file)
    # load the private key file
    privk = privatekey.PrivateKey()
    privk.load(args.privatekeyfile)
    # Create a new instance of Certificate
    certobj = cert.Certificate(private_key=privk)
    # Generate the certificate
    certobj.gen_self_signed(
        subject=configdata["subject"],
        dns_names=configdata["dnsnames"],
        ip_addresses=configdata["ipaddresses"],
    )
    # create the output directory
    dirs.mkdir(args.dir)
    # Save the certificate
    status = certobj.save(fp_crt, force=args.force)
    # Early escape if could not save it
    if not status:
        print(
            "Error in saving the certificate. Maybe you need to overwrite an existing "
            + "files with the --force option",
        )
        sys.exit(1)
    # Show where cert file has been saved
    print("\r\nCertificate file saved to %s\r\n" % fp_crt)
    # Read the certificate back
    data = files.read(fp_crt)
    # Print it on screen
    print(data.decode("UTF-8"))
    print("\r\nFINGERPRINTS\r\n")
    print("%s\r" % (certobj.hash_fingerprint_pem_cert(fp_crt, "MD5")))
    print("%s\r" % (certobj.hash_fingerprint_pem_cert(fp_crt, "SHA-1")))
    print("\r\n")


if __name__ == "__main__":
    main()
