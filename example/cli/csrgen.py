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
"""Basic x509 Certificate Signing Request (CSR) generator CLI
"""
import argparse
import sys

import yaml
from cryptopyutils import csr
from cryptopyutils import dirs
from cryptopyutils import files
from cryptopyutils import privatekey


def main():
    """Basic x509 Certificate Signing Request (CSR) generator CLI"""
    parser = argparse.ArgumentParser(
        description="Basic x509 Certificate Signing Request (CSR) generator CLI",
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
    parser.add_argument(
        "-c",
        "--challenge",
        help="Challenge password shared with the certificate issuer",
        type=str,
        required=True,
    )
    parser.add_argument("-D", "--dir", help="Output directory", type=str, required=True)
    parser.add_argument("--force", help="Force file overwriting", action="store_true")
    args = parser.parse_args()
    # future CSR filepath
    fp_csr = files.csr(args.name, args.dir)
    # load the yaml configuration file
    with open(args.config, "r") as file:
        configdata = yaml.safe_load(file)
    # load the private key file
    privk = privatekey.PrivateKey()
    privk.load(args.privatekeyfile)
    # Create a new instance of CSR
    csrobj = csr.CSR(private_key=privk)
    # Generate the csr
    csrobj.gen(
        args.challenge,
        subject=configdata["subject"],
        dns_names=configdata["dnsnames"],
        ip_addresses=configdata["ipaddresses"],
    )
    # create dir
    dirs.mkdir(args.dir)
    # Save the CSR
    status = csrobj.save(fp_csr, force=args.force)
    # Early escape if could not save it
    if not status:
        print(
            "Error in saving the CSR. Maybe you need to overwrite an existing "
            + "files with the --force option",
        )
        sys.exit(1)
    print("\r\nCSR file saved to %s\r\n" % fp_csr)
    # Read the CSR back
    data = files.read(fp_csr)
    # Print it on screen
    print(data.decode("UTF-8"))


if __name__ == "__main__":
    main()
