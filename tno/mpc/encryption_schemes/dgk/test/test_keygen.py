"""
This module tests the key generation of DGK.
"""

import pytest
import sympy

from tno.mpc.encryption_schemes.dgk import DGK, DGKPublicKey, DGKSecretKey
from tno.mpc.encryption_schemes.dgk.dgk import pow_mod  # type: ignore[attr-defined]

key_values = [
    (10, 100, 11),
    (25, 700, 101),
    (10, 500, 773),
    (5, 500, 113),
    (7, 500, 101),
    (8, 500, 101),
    (8, 500, 113),
]
key_sets = []
multiple_key_sets = []

# Create parameters
for i in range(10):
    for values in key_values:
        key_pair = DGK.generate_key_material(*values)
        if i == 0:
            key_sets.append(key_pair)
        multiple_key_sets.append(key_pair)


@pytest.mark.parametrize("public_key, secret_key", key_sets)
@pytest.mark.parametrize("precision", [0, 1])
def test_encryption_creation(
    public_key: DGKPublicKey, secret_key: DGKSecretKey, precision: int
) -> None:
    """
    Test whether the creation of the encryption works with the keys

    :param public_key: DGK public key for this scheme
    :param secret_key: DGK secret key for this scheme
    :param precision: Precision of the DGK scheme
    """
    DGK(public_key, secret_key, precision)
    DGK(public_key, None, precision)

    # Simply check for no exceptions
    assert 1


@pytest.mark.parametrize("public_key, secret_key", multiple_key_sets)
def test_g_order(public_key: DGKPublicKey, secret_key: DGKSecretKey) -> None:
    r"""
    Test whether the generated value $g$ has the right order.

    :param public_key: Generated DGK public key
    :param secret_key: Generated DGK secret key
    """
    assert pow_mod(public_key.g, secret_key.v_p, public_key.n) != 1
    assert pow_mod(public_key.g, secret_key.v_q, public_key.n) != 1
    assert pow_mod(public_key.g, public_key.u, public_key.n) != 1
    assert pow_mod(public_key.g, secret_key.v_p * secret_key.v_q, public_key.n) != 1
    assert pow_mod(public_key.g, secret_key.v_p * public_key.u, public_key.n) != 1
    assert pow_mod(public_key.g, secret_key.v_q * public_key.u, public_key.n) != 1
    assert pow_mod(public_key.g, secret_key.v_p_v_q * public_key.u, public_key.n) == 1


@pytest.mark.parametrize("public_key, secret_key", multiple_key_sets)
def test_h_order(public_key: DGKPublicKey, secret_key: DGKSecretKey) -> None:
    r"""
    Test whether the generated value $h$ has the right order.

    :param public_key: Generated DGK public key
    :param secret_key: Generated DGK secret key
    """
    assert pow_mod(public_key.h, secret_key.v_p, public_key.n) != 1
    assert pow_mod(public_key.h, secret_key.v_q, public_key.n) != 1
    assert pow_mod(public_key.h, secret_key.v_p_v_q, public_key.n) == 1


@pytest.mark.parametrize("public_key, secret_key", key_sets)
@pytest.mark.parametrize("precision", [0, 1])
def test_decryption_table_completeness(
    public_key: DGKPublicKey, secret_key: DGKSecretKey, precision: int
) -> None:
    r"""
    Test whether the decryption table contains every possible key value. I.e. it should contain $g^{v_pm} \pmod p$, for
    all values of $m$

    :param public_key: DGK public key to be used by the scheme
    :param secret_key: DGK secret key to be used by the scheme
    :param precision: Precision to be used by the DGK scheme
    """
    scheme = DGK(public_key, secret_key, precision)
    assert scheme.decryption_table is not None
    for plaintext in range(0, public_key.u):
        assert (
            pow_mod(public_key.g, secret_key.v_p * plaintext, secret_key.p)
            in scheme.decryption_table
        )


@pytest.mark.parametrize("public_key, secret_key", key_sets)
@pytest.mark.parametrize("precision", [0, 1])
def test_decryption_uniqueness(
    public_key: DGKPublicKey, secret_key: DGKSecretKey, precision: int
) -> None:
    """
    Check whether all keys from the decryption table have a unique decryption. I.e. check if every plaintext is present.

    :param public_key: DGK public key to be used by the scheme.
    :param secret_key: DGK secret key to be used by the scheme.
    :param precision: Precision to be used by the DGK scheme.
    """
    scheme = DGK(public_key, secret_key, precision)
    assert scheme.decryption_table is not None
    for plaintext in range(0, public_key.u):
        assert plaintext in scheme.decryption_table.values()


@pytest.mark.parametrize("u", (1, 4, 33, 44, 1000, 33 * 55, -3, 0))
def test_non_prime_u_exception(u: int) -> None:
    """
    Test if trying to create a key with a non-prime u raises an exception

    :param u: Non-prime u value.
    """
    with pytest.raises(ValueError) as error:
        DGK.generate_key_material(1, 100, u)
    assert str(error.value) == "u is not a prime"


@pytest.mark.parametrize("public_key, secret_key", multiple_key_sets)
def test_prime_values(public_key: DGKPublicKey, secret_key: DGKSecretKey) -> None:
    """
    Test if the key values that need to be prime are prime.

    :param public_key: DGK public key to be used by the scheme.
    :param secret_key: DGK secret key to be used by the scheme.
    """
    assert sympy.isprime(public_key.u)
    assert sympy.isprime(secret_key.p)
    assert sympy.isprime(secret_key.q)
    assert sympy.isprime(secret_key.v_p)
    assert sympy.isprime(secret_key.v_q)


@pytest.mark.parametrize("public_key, secret_key", multiple_key_sets)
def test_divisibility(public_key: DGKPublicKey, secret_key: DGKSecretKey) -> None:
    """
    Test if the key values that need to be prime are prime.

    :param public_key: DGK public key to be used by the scheme.
    :param secret_key: DGK secret key to be used by the scheme.
    """
    assert public_key.n == secret_key.p * secret_key.q

    assert (secret_key.p - 1) % public_key.u == 0
    assert (secret_key.q - 1) % public_key.u == 0

    assert (secret_key.p - 1) % secret_key.v_p == 0
    assert (secret_key.q - 1) % secret_key.v_q == 0
