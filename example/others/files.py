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
"""Files Example
"""
import os
from pathlib import Path

from cryptopyutils import files

if __name__ == "__main__":

    # Generate a filepath (but does not create the file)
    DIR_PATH = "/tmp"
    HOST = "www.example.com"
    EXT = "pem"
    file_path = files.generate(HOST, DIR_PATH, EXT)
    print("Filepath generated : %s" % file_path)

    # for a key
    DIR_PATH = "/tmp/test"
    file_path = files.key(HOST, DIR_PATH)
    print(
        "Filepath generated for a key with a specified directory"
        + "`%s` : %s" % (DIR_PATH, file_path),
    )

    # for a crt
    file_path = files.crt(HOST, DIR_PATH)
    print("Filepath generated for a crt : %s" % file_path)

    # for a csr
    file_path = files.csr(HOST, DIR_PATH)
    print("Filepath generated for a csr : %s" % file_path)

    # for a pem
    file_path = files.pem(HOST, DIR_PATH)
    print("Filepath generated for a pem : %s" % file_path)

    # for a der
    file_path = files.der(HOST, DIR_PATH)
    print("Filepath generated for a der : %s" % file_path)

    # for a pub
    file_path = files.pub(HOST, DIR_PATH)
    print("Filepath generated for a pub : %s" % file_path)

    # Other utils

    # create a temporary file
    FILEPATH = "/tmp/tmpfile12395698744"

    if os.path.exists(FILEPATH):
        os.remove(FILEPATH)

    # check if it exists
    print(
        ("File %s should not exist - should return False" + ": %s")
        % (FILEPATH, files.file_exists(FILEPATH)),
    )
    # touch
    Path(FILEPATH).touch()
    # check again if it exists
    print(
        ("File %s should exist - should return True" + ": %s")
        % (FILEPATH, files.file_exists(FILEPATH)),
    )

    # print its chmod status before
    print("File %s chmod status is %s" % (FILEPATH, files.get_chmod(FILEPATH)))

    # change its chmod to 0o700
    files.set_chmod(FILEPATH, 0o700)

    # read its chmod status
    print("File %s new chmod status is %s" % (FILEPATH, files.get_chmod(FILEPATH)))

    # write some text
    DATA = "sample text"
    print("Data to be written : %s" % DATA)
    files.write(FILEPATH, DATA, istext=True)

    # read the text back
    data_read = files.read(FILEPATH, istext=True)
    print("Data read back : %s" % data_read)

    # destroy it
    if os.path.exists(FILEPATH):
        os.remove(FILEPATH)

    # touch
    Path(FILEPATH).touch()

    # write some binary data
    DATA_BIN = b"sample text"
    print("Data to be written : %s" % DATA_BIN)
    files.write(FILEPATH, DATA_BIN)

    # read the binary data back
    data_bin_read = files.read(FILEPATH)
    print("Data read back : %s" % data_bin_read)

    # destroy it
    if os.path.exists(FILEPATH):
        os.remove(FILEPATH)
