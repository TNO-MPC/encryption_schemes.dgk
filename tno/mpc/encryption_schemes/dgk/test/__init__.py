"""
Testing module of the tno.mpc.encryption_schemes.dgk library
"""
from contextlib import contextmanager
from typing import Iterator

import pytest

from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncryptionSchemeWarning,
)

from tno.mpc.encryption_schemes.dgk import DGK
from tno.mpc.encryption_schemes.dgk.dgk import DGKCiphertext, Plaintext


def encrypt_with_freshness(m: Plaintext, scheme: DGK, safe: bool) -> DGKCiphertext:
    """
    Encrypt a plaintext in safe or unsafe mode.

    Safe mode will yield a fresh ciphertext, unsafe mode will yield a non-fresh ciphertext.

    :param m: Plaintext message to be encrypted
    :param scheme: Scheme to encrypt the message with
    :param safe: Perform safe encrypt if true, unsafe encrypt otherwise
    :return: PaillierCiphertext object with requested freshness
    """
    if safe:
        return scheme.encrypt(m)
    return scheme.unsafe_encrypt(m)


@contextmanager
def conditional_pywarn(truthy: bool, match: str) -> Iterator[None]:
    """
    Conditionally wraps statement in pytest.warns context manager.

    :param truthy: Flags whether statement should be ran in pytest.warns
    :param match: Match parameter for pytest.warns
    :return: _description_
    :yield: _description_
    """
    if truthy:
        with pytest.warns(EncryptionSchemeWarning) as record:
            yield
            assert (
                len(record) >= 1  # Duplicate warnings possible
            ), f"Expected to catch one EncryptionSchemeWarning, caught {len(record)}."
            for rec_msg in (str(rec.message) for rec in record):
                assert (
                    rec_msg == match
                ), f'Expected message "{match}", received message "{rec_msg}".'
    else:
        yield


def dgk_scheme(with_precision: bool) -> DGK:
    """
    Constructs a DGK scheme

    :param with_precision: boolean specifying whether to use precision in scheme
    :return: Initialized DGK scheme with, or without, precision
    """
    public_key, secret_key = DGK.generate_key_material(8, 200, 101)
    if with_precision:
        return DGK(
            public_key,
            secret_key,
            precision=1,
            nr_of_threads=3,
            debug=False,
            start_generation=False,
        )
    return DGK(
        public_key,
        secret_key,
        nr_of_threads=3,
        debug=False,
        start_generation=False,
    )
