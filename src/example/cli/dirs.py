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
"""Dirs Manipulation CLI
"""
import argparse
import sys

from cryptopyutils import dirs


def main():
    """Dirs Manipulation CLI"""
    parser = argparse.ArgumentParser(description="DIRECTORY MANIPULATION")
    parser.add_argument("action", choices=["mkdir", "rmdir"], help="Action")
    parser.add_argument("dir", help="Directory")
    args = parser.parse_args()
    if args.action == "mkdir":
        dirs.mkdir(args.dir)
        print("Created folder : %s" % args.dir)
    elif args.action == "rmdir":
        # prevent accidental system damage
        if args.dir in [
            "/",
            "/etc",
            "/bin",
            "/boot",
            "/dev",
            "/home",
            "/init",
            "/lib",
            "/lib32",
            "/lib64",
            "/libx32",
            "/lost+found",
            "/media",
            "/mnt",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/snap",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/var",
            "~",
            "$HOME",
        ]:
            print("Cannot remove system or home directories")
            sys.exit(1)
        # remove
        dirs.rmdir(args.dir)
        print("Removed folder : %s" % args.dir)
    else:
        print("Command not supported")
        sys.exit(1)


if __name__ == "__main__":
    main()
