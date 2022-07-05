# -*- coding: utf-8 -*-
"""
Keypair
"""


class Keypair:
    """Keypair object"""

    def __init__(
        config=None,
        key_alg=None,
        private_key=None,
        public_key=None,
        output_directory=None,
        encoding=None,
        hash_alg=None,
    ):
        self.key_alg = key_alg
        self.private_key = private_key
        self.public_key = public_key
        self.output_directory = output_directory
        self.encoding = encoding
        self.hash_alg = hash_alg
