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
""" Constant time comparison CLI

This snippet compares a left series of bytes to a right series.
It uses a constant time function to avoid timing attacks.
"""
import argparse

from cryptopyutils import utils


def main():
    """Constant time comparison"""
    parser = argparse.ArgumentParser(
        description="CONSTANT TIME COMPARISON",
    )
    parser.add_argument("left", help="left", type=str)
    parser.add_argument("right", help="right", type=str)
    args = parser.parse_args()
    left = args.left.encode("UTF-8")
    right = args.right.encode("UTF-8")
    comparison = utils.compare_bytes(left, left)
    print(
        "%s is the result of the comparison of `%s` with `%s`"
        % (comparison, left, right),
    )


if __name__ == "__main__":
    main()
