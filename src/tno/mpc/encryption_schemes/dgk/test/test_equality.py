"""
This module tests the equality functions of DGK.
"""

from tno.mpc.encryption_schemes.dgk import DGK

public_key, secret_key = DGK.generate_key_material(10, 100, 11)
encryption_scheme = DGK(public_key, secret_key)


def test_keys_equality() -> None:
    """
    Test whether equality of both the secret and public key of DGK was implemented properly.
    """
    assert encryption_scheme.public_key == encryption_scheme.public_key
    assert encryption_scheme.secret_key == encryption_scheme.secret_key


def test_cipher_equality() -> None:
    """
    Test whether equality of DGK ciphertexts was implemented properly.
    """
    cipher = encryption_scheme.encrypt(3)
    assert cipher == cipher  # pylint: disable=comparison-with-itself
    assert cipher == cipher.copy()


def test_encryption_scheme_equality() -> None:
    """
    Test whether equality of DGK encryption schemes was implemented properly.
    """
    assert (
        encryption_scheme == encryption_scheme  # pylint: disable=comparison-with-itself
    )
