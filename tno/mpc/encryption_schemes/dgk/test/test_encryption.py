"""
This module tests the encryption functionality of DGK.
"""
import itertools
import math
import secrets
from typing import Dict, Union, cast

import pytest
from _pytest.fixtures import SubRequest

from tno.mpc.encryption_schemes.dgk import DGK
from tno.mpc.encryption_schemes.dgk.dgk import WARN_INEFFICIENT_HOM_OPERATION
from tno.mpc.encryption_schemes.dgk.test import (
    conditional_pywarn,
    encrypt_with_freshness,
)

public_key, secret_key = DGK.generate_key_material(64, 400, 105929)

parameter_values_a = [
    -50,
    -51,
    -49 - 4,
    -6,
    -5,
    0,
    3,
    4,
    5,
    6,
    49,
    50,
    51,
    434,
    6554,
    2342,
    434898,
    90,
]
parameter_values_b = [
    -50,
    -51,
    -49 - 4,
    -6,
    -5,
    -8,
    0,
    2,
    4,
    5,
    6,
    49,
    50,
    51,
    23244,
    33254,
    33452,
    90,
]

parameter_values_a_b = set(parameter_values_a + parameter_values_b)


def limit_to_message_space(value: float, encryption_scheme: DGK) -> float:
    """
    Limit a value in such a way that it fits in the message space.

    :param value: Value to be limited.
    :param encryption_scheme: DGK scheme with which the message value should be encrypted.
    :return: Limited value (or identical of no limiting was needed).
    """
    if encryption_scheme.precision > 0 and (
        value > encryption_scheme.max_value or value < encryption_scheme.min_value
    ):
        value /= 10**encryption_scheme.precision

    if value < 0:
        return float(
            round(value % encryption_scheme.min_value, encryption_scheme.precision)
        )
    # else
    return float(
        round(value % encryption_scheme.max_value, encryption_scheme.precision)
    )


@pytest.fixture(params=[0, 1])
def precision_value(request: SubRequest) -> int:
    """
    Possible precision values of the cached DGK schemes.

    :param request: Request for a DGK scheme.
    :return: Integer for which a DGK scheme exists.
    """
    return cast(int, request.param)


# Cache encryption_schemes for speed
_dgk: Dict[int, DGK] = {}


@pytest.fixture(name="encryption_scheme")
def fixture_encryption_scheme(
    precision_value: int,  # pylint: disable=redefined-outer-name
) -> DGK:
    """
    Get DGK encryption scheme for the given precision value, if it doesn't exist make it and
    store it for later re-use.

    :param precision_value: Precision value of the DGK scheme
    :return: DGK scheme with the given precision_value.
    """
    if precision_value in _dgk:
        return _dgk[precision_value]
    dgk = DGK(public_key, secret_key, precision=precision_value)
    _dgk[precision_value] = dgk
    return dgk


# Cache encryption_schemes without secret key (i.e. public) for speed
_public_dgk: Dict[int, DGK] = {}


@pytest.fixture(name="public_encryption_scheme")
def fixture_public_encryption_scheme(
    precision_value: int,  # pylint: disable=redefined-outer-name
) -> DGK:
    """
    Get DGK encryption scheme without secret key (i.e. public) for the given precision value,
    if it doesn't exist make it and store it for later re-use.

    :param precision_value: Precision value of the DGK scheme
    :return: DGK scheme with the given precision_value (without secret key).
    """
    if precision_value in _public_dgk:
        return _public_dgk[precision_value]
    dgk = DGK(public_key, None, precision=precision_value)
    _public_dgk[precision_value] = dgk
    return dgk


# Cache encryption_schemes without full decryption for speed
_dgk_no_full_decryption: Dict[int, DGK] = {}


@pytest.fixture(name="encryption_scheme_no_decryption")
def fixture_encryption_scheme_no_decryption(
    precision_value: int,  # pylint: disable=redefined-outer-name
) -> DGK:
    """
    Get DGK encryption scheme without full decryption functionality. Can only check if a ciphertext equals 0.

    :param precision_value: Precision value of the DGK scheme
    :return: DGK scheme with the given precision_value (without secret key).
    """
    if precision_value in _dgk_no_full_decryption:
        return _dgk_no_full_decryption[precision_value]
    dgk = DGK(public_key, secret_key, precision=precision_value, full_decryption=False)
    _dgk_no_full_decryption[precision_value] = dgk
    return dgk


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_public_encryption(
    public_encryption_scheme: DGK,
    encryption_scheme: DGK,
    plain_value: Union[float, int],
) -> None:
    """
    Test the encryption functionality of a DGK scheme without a secret key.

    :param public_encryption_scheme: DGK encryption scheme without a secret key.
    :param encryption_scheme: DGK encryption scheme with secret key (to test the decryption).
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    message = public_encryption_scheme.encrypt(plain_value)
    assert encryption_scheme.decrypt(message) == plain_value


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_cipher_randomization(
    encryption_scheme: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test the rerandomization of a DGK ciphertext.

    :param encryption_scheme: DGK encryption scheme to be used for generating ciphertexts and
        randomness.
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    cipher = encryption_scheme.encrypt(plaintext=plain_value)
    randomized_cipher = cipher.copy()

    assert randomized_cipher == cipher

    randomized_cipher.apply_randomness(secrets.randbelow(99) + 2)
    assert cipher != randomized_cipher


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_safe_encryption(
    encryption_scheme: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test the encryption functionality of a DGK scheme with a secret key.

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    encrypted_value = encryption_scheme.encrypt(plain_value)
    decrypted_value = encryption_scheme.decrypt(encrypted_value)

    assert encrypted_value.fresh
    assert decrypted_value == plain_value


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_unsafe_encryption(
    encryption_scheme: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test the unsafe encryption functionality of a DGK scheme with a secret key.

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    encrypted_value = encryption_scheme.unsafe_encrypt(plain_value)
    decrypted_value = encryption_scheme.decrypt(encrypted_value)

    assert not encrypted_value.fresh
    assert decrypted_value == plain_value


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_encryption_with_rerandomization(
    encryption_scheme: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test the encryption functionality of a DGK scheme with a secret key with respect to rerandomization.

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    encrypted_value = encryption_scheme.unsafe_encrypt(plain_value)
    assert not encrypted_value.fresh

    encrypted_value_prime = encrypted_value.copy()
    assert not encrypted_value_prime.fresh

    encrypted_value_prime.randomize()
    assert encrypted_value_prime.fresh
    decrypted_value_prime = encryption_scheme.decrypt(encrypted_value_prime)

    assert encrypted_value != encrypted_value_prime
    assert decrypted_value_prime == plain_value


@pytest.mark.parametrize("plain_value", parameter_values_a_b)
def test_copy(encryption_scheme: DGK, plain_value: Union[float, int]) -> None:
    """
    Test correct copy behaviour of a ciphertext for both fresh and non-fresh ciphertext.

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_value: Plaintext message that is to be encrypted.
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    encrypted_value = encryption_scheme.encrypt(plain_value)
    encrypted_value_prime = encrypted_value.copy()  # copy fresh to non-fresh
    encrypted_value_prime_prime = (
        encrypted_value_prime.copy()
    )  # copy non-fresh to non-fresh

    assert encrypted_value.fresh
    assert not encrypted_value_prime.fresh
    assert not encrypted_value_prime_prime.fresh
    assert encrypted_value == encrypted_value_prime
    assert encrypted_value is not encrypted_value_prime
    assert encrypted_value_prime == encrypted_value_prime_prime
    assert encrypted_value_prime is not encrypted_value_prime_prime


@pytest.mark.parametrize(
    "is_fresh_a, is_fresh_b",
    itertools.product((True, False), (True, False)),
)
@pytest.mark.parametrize("plain_a", parameter_values_a)
@pytest.mark.parametrize("plain_b", parameter_values_b)
def test_add(
    encryption_scheme: DGK,
    plain_a: Union[float, int],
    plain_b: Union[float, int],
    is_fresh_a: bool,
    is_fresh_b: bool,
) -> None:
    """
    Test whether two ciphertexts can be added (i.e. the plaintexts are added).

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_a: First plaintext message to be encrypted.
    :param plain_b: Second plaintext message to be encrypted and added to the first.
    :param is_fresh_a: freshness of first ciphertext
    :param is_fresh_b: freshness of second ciphertext
    """
    plain_a = limit_to_message_space(plain_a, encryption_scheme)
    plain_b = limit_to_message_space(plain_b, encryption_scheme)

    # limit to message space
    if plain_a + plain_b > encryption_scheme.max_value:
        plain_b = encryption_scheme.max_value - 1 - plain_a
    elif plain_a + plain_b < encryption_scheme.min_value:
        plain_b = encryption_scheme.min_value + 1 - plain_a

    sum_ = plain_a + plain_b

    # verify message space limiting
    assert sum_ <= encryption_scheme.max_value
    assert sum_ >= encryption_scheme.min_value

    encrypted_a = encrypt_with_freshness(plain_a, encryption_scheme, is_fresh_a)
    encrypted_b = encrypt_with_freshness(plain_b, encryption_scheme, is_fresh_b)

    with conditional_pywarn(is_fresh_a or is_fresh_b, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum = encrypted_a + encrypted_b

    assert not encrypted_a.fresh
    assert not encrypted_b.fresh
    assert encrypted_sum.fresh == (is_fresh_a or is_fresh_b)

    # Test summation with two ciphertexts
    assert encryption_scheme.decrypt(encrypted_sum) == sum_

    # Test by passing non-encrypted plain_b
    encrypted_a = encrypt_with_freshness(plain_a, encryption_scheme, is_fresh_a)

    with conditional_pywarn(is_fresh_a, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum = encrypted_a + plain_b
    assert not encrypted_a.fresh
    assert encrypted_sum.fresh == is_fresh_a
    assert encryption_scheme.decrypt(encrypted_sum) == sum_


@pytest.mark.parametrize(
    "is_fresh_a, is_fresh_b",
    itertools.product((True, False), (True, False)),
)
@pytest.mark.parametrize("plain_a", parameter_values_a)
@pytest.mark.parametrize("plain_b", parameter_values_b)
def test_subtraction(
    encryption_scheme: DGK,
    plain_a: Union[float, int],
    plain_b: Union[float, int],
    is_fresh_a: bool,
    is_fresh_b: bool,
) -> None:
    """
    Test whether two ciphertexts can be subtracted (i.e. the plaintexts are subtracted).

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_a: First plaintext message to be encrypted.
    :param plain_b: Second plaintext message to be encrypted and subtracted from the first.
    :param is_fresh_a: freshness of first ciphertext
    :param is_fresh_b: freshness of second ciphertext
    """
    plain_a = limit_to_message_space(plain_a, encryption_scheme)
    plain_b = limit_to_message_space(plain_b, encryption_scheme)

    # limit to message space
    if plain_a - plain_b > encryption_scheme.max_value:
        plain_b = plain_a - encryption_scheme.max_value + 1
    elif plain_a - plain_b < encryption_scheme.min_value:
        plain_b = plain_a - encryption_scheme.min_value - 1

    subtraction = plain_a - plain_b

    # verify message space limiting
    assert subtraction <= encryption_scheme.max_value
    assert subtraction >= encryption_scheme.min_value

    encrypted_a = encrypt_with_freshness(plain_a, encryption_scheme, is_fresh_a)
    encrypted_b = encrypt_with_freshness(plain_b, encryption_scheme, is_fresh_b)

    with conditional_pywarn(is_fresh_a or is_fresh_b, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_subtraction = encrypted_a - encrypted_b

    assert not encrypted_a.fresh
    assert not encrypted_b.fresh
    assert encrypted_subtraction.fresh == (is_fresh_a or is_fresh_b)

    # Test summation with two ciphertexts
    assert encryption_scheme.decrypt(encrypted_subtraction) == subtraction

    # Test by passing non-encrypted plain_b
    encrypted_a = encrypt_with_freshness(plain_a, encryption_scheme, is_fresh_a)

    with conditional_pywarn(is_fresh_a, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_subtraction = encrypted_a - plain_b
    assert not encrypted_a.fresh
    assert encrypted_subtraction.fresh == is_fresh_a
    assert encryption_scheme.decrypt(encrypted_subtraction) == subtraction


@pytest.mark.parametrize("is_fresh_a", (True, False))
@pytest.mark.parametrize("plain_a", parameter_values_a)
@pytest.mark.parametrize("plain_b", parameter_values_b)
def test_mul(
    encryption_scheme: DGK,
    plain_a: Union[float, int],
    plain_b: Union[float, int],
    is_fresh_a: bool,
) -> None:
    """
    Test whether a ciphertext can be multiplied with a scalar.

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_a: First plaintext message to be encrypted.
    :param plain_b: Second plaintext message to be multiplied with the first as a plaintext scalar.
    :param is_fresh_a: freshness of first ciphertext
    """
    plain_a = limit_to_message_space(plain_a, encryption_scheme)
    plain_b = limit_to_message_space(plain_b, encryption_scheme)
    plain_b = int(round(plain_b))

    # Limit to message space
    if plain_a * plain_b > encryption_scheme.max_value:
        limit_factor = math.ceil(plain_a * plain_b / encryption_scheme.max_value)
        plain_a = math.floor(plain_a / limit_factor)
    elif plain_a * plain_b < encryption_scheme.min_value:
        limit_factor = math.ceil(plain_a * plain_b / encryption_scheme.min_value)
        plain_a = math.ceil(plain_a / limit_factor)

    mul = plain_a * plain_b

    assert mul <= encryption_scheme.max_value
    assert mul >= encryption_scheme.min_value

    encrypted_a = encrypt_with_freshness(plain_a, encryption_scheme, is_fresh_a)

    with conditional_pywarn(is_fresh_a, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_mul = encrypted_a * plain_b

    assert not encrypted_a.fresh
    assert encrypted_mul.fresh == is_fresh_a

    assert encryption_scheme.decrypt(encrypted_mul) == mul


@pytest.mark.parametrize("is_fresh", (True, False))
@pytest.mark.parametrize(
    "plain_value",
    parameter_values_a_b,
)
def test_neg(
    encryption_scheme: DGK, plain_value: Union[float, int], is_fresh: bool
) -> None:
    """
    Test whether a ciphertext can be negated (i.e. negation of the underlying plaintext).

    :param encryption_scheme: DGK encryption scheme with secret key.
    :param plain_value: First plaintext message to be encrypted and negated.
    :param is_fresh: freshness of ciphertext
    """
    plain_value = limit_to_message_space(plain_value, encryption_scheme)

    encrypted_value = encrypt_with_freshness(plain_value, encryption_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_neg = encryption_scheme.neg(encrypted_value)

    assert not encrypted_value.fresh
    assert encrypted_neg.fresh == is_fresh

    assert encryption_scheme.decrypt(encrypted_neg) == -plain_value


@pytest.mark.parametrize("plain_value", (0,))
def test_zero(
    encryption_scheme_no_decryption: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test whether zero plaintext can be determined succesfully.

    :param encryption_scheme_no_decryption: DGK encryption scheme without full decryption
    :param plain_value: 0 plaintext value
    """
    for _ in range(10):
        encrypted_value = encryption_scheme_no_decryption.encrypt(plain_value)

        assert encrypted_value.is_zero()
        assert encryption_scheme_no_decryption.is_zero(encrypted_value)


@pytest.mark.parametrize("plain_value", [_ + -5 for _ in range(11) if _ != 5])
def test_non_zero(
    encryption_scheme_no_decryption: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test whether non-zero plaintext can be determined successfully.

    :param encryption_scheme_no_decryption: DGK encryption scheme without full decryption
    :param plain_value: non-zero plaintext value
    """
    encrypted_value = encryption_scheme_no_decryption.encrypt(plain_value)

    assert not encrypted_value.is_zero()
    assert not encryption_scheme_no_decryption.is_zero(encrypted_value)


@pytest.mark.parametrize("plain_value", [_ + -5 for _ in range(11)])
def test_no_decryption(
    encryption_scheme_no_decryption: DGK, plain_value: Union[float, int]
) -> None:
    """
    Test whether plaintext decryption gives an exception on a scheme that cannot do decryption.

    :param encryption_scheme_no_decryption: DGK encryption scheme without full decryption
    :param plain_value: plinatext value
    """
    encrypted_value = encryption_scheme_no_decryption.encrypt(plain_value)

    assert encryption_scheme_no_decryption.decryption_table is None
    with pytest.raises(ValueError):
        encryption_scheme_no_decryption.decrypt(encrypted_value)
