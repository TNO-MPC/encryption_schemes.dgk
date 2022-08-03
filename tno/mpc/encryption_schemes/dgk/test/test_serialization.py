"""
This module tests the (de)serialization of DGK.
"""
import asyncio
from typing import Any, Tuple

import pytest

from tno.mpc.communication import Pool
from tno.mpc.communication.test.pool_fixtures_http import (  # pylint: disable=unused-import
    event_loop,
    fixture_pool_http_2p,
    fixture_pool_http_3p,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncryptionSchemeWarning,
)

from tno.mpc.encryption_schemes.dgk import (
    DGK,
    DGKCiphertext,
    DGKPublicKey,
    DGKSecretKey,
)
from tno.mpc.encryption_schemes.dgk.dgk import WARN_UNFRESH_SERIALIZATION
from tno.mpc.encryption_schemes.dgk.test import dgk_scheme

encryption_scheme = DGK(*DGK.generate_key_material(10, 100, 11))


def test_public_key_serialization() -> None:
    """
    Test whether the DGK public key is (de)serialized properly.
    """
    serialized = encryption_scheme.public_key.serialize()
    assert encryption_scheme.public_key == DGKPublicKey.deserialize(serialized)


def test_secret_key_serialization() -> None:
    """
    Test whether the DGK secret key is (de)serialized properly.
    """
    serialized = encryption_scheme.secret_key.serialize()
    assert encryption_scheme.secret_key == DGKSecretKey.deserialize(serialized)


def test_cipher_serialization() -> None:
    """
    Test whether a DGK Ciphertext is (de)serialized properly.
    """
    cipher: DGKCiphertext = encryption_scheme.encrypt(4)
    serialized = cipher.serialize()
    assert cipher == DGKCiphertext.deserialize(serialized)


@pytest.mark.parametrize("with_precision", (True, False))
def test_encryption_scheme_serialization_no_share(with_precision: bool) -> None:
    """
    Test to determine whether the DGK scheme serialization works properly for schemes
    when the secret key SHOULD NOT be serialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    # by default the secret key is not serialized, but equality should then still hold
    scheme_prime = DGK.deserialize(scheme.serialize())
    scheme.shut_down()
    scheme_prime.shut_down()
    # secret key is still shared due to local instance sharing
    assert scheme_prime.secret_key is scheme_prime.secret_key
    assert scheme == scheme_prime

    # this time empty the list of global instances after serialization
    scheme.boot_generation()
    scheme_serialized = scheme.serialize()
    DGK.clear_instances()
    scheme_prime2 = DGK.deserialize(scheme_serialized)
    scheme.shut_down()
    scheme_prime2.shut_down()
    assert scheme_prime2.secret_key is None
    assert scheme == scheme_prime2


@pytest.mark.parametrize("with_precision", (True, False))
def test_encryption_scheme_serialization_share(with_precision: bool) -> None:
    """
    Test to determine whether the DGK scheme serialization works properly for schemes
    when the secret key SHOULD be serialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    scheme.share_secret_key = True
    # We indicated that the secret key should be serialized, so this should be equal
    scheme_prime = DGK.deserialize(scheme.serialize())
    scheme_prime.shut_down()
    scheme.shut_down()
    assert scheme == scheme_prime


@pytest.mark.parametrize("with_precision", (True, False))
def test_unrelated_instances(with_precision: bool) -> None:
    """
    Test whether the from_id_arguments and id_from_arguments methods works as intended.
    The share_secret_key variable should not influence the identifier.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    public_key = scheme.public_key
    secret_key = scheme.secret_key

    dgk_1 = DGK(
        public_key=public_key, secret_key=None, precision=0, share_secret_key=False
    )
    dgk_1_prime = DGK(
        public_key=public_key, secret_key=secret_key, precision=0, share_secret_key=True
    )
    assert dgk_1.identifier == dgk_1_prime.identifier
    dgk_1.save_globally()
    dgk_2 = DGK.from_id_arguments(public_key=public_key, precision=0)
    dgk_3 = DGK(public_key=public_key, precision=10, secret_key=None)
    assert dgk_1.identifier != dgk_3.identifier
    with pytest.raises(KeyError):
        _dgk_4 = DGK.from_id_arguments(public_key=public_key, precision=10)

    dgk_3.save_globally()
    dgk_4 = DGK.from_id_arguments(public_key=public_key, precision=10)
    dgk_1.shut_down()
    dgk_1_prime.shut_down()
    dgk_2.shut_down()
    dgk_3.shut_down()
    dgk_4.shut_down()
    scheme.shut_down()

    assert dgk_1 is dgk_2
    assert dgk_1 == dgk_2
    assert dgk_1 is not dgk_3
    assert dgk_1 != dgk_3
    assert dgk_2 is not dgk_4
    assert dgk_2 != dgk_4
    assert dgk_3 is dgk_4
    assert dgk_3 == dgk_4


@pytest.mark.parametrize("with_precision", (True, False))
def test_related_serialization(with_precision: bool) -> None:
    """
    Test whether deserialization of ciphertexts results in correctly deserialized schemes. Because
    ciphertexts are connected to schemes, you want ciphertexts coming from the same scheme to
    still have the same scheme when they are deserialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    ciphertext_1 = scheme.encrypt(1)
    ciphertext_2 = scheme.encrypt(2)
    ser_1 = ciphertext_1.serialize()
    ser_2 = ciphertext_2.serialize()
    new_ciphertext_1 = DGKCiphertext.deserialize(ser_1)
    new_ciphertext_2 = DGKCiphertext.deserialize(ser_2)

    new_ciphertext_1.scheme.shut_down()
    scheme.shut_down()

    assert (
        new_ciphertext_1.scheme
        is new_ciphertext_2.scheme
        is ciphertext_1.scheme
        is ciphertext_2.scheme
    )


@pytest.mark.parametrize("with_precision", (True, False))
def test_instances_from_security_param(with_precision: bool) -> None:
    """
    Test whether the get_instance_from_sec_param method works as intended. If a dgk scheme
    with the given parameters has already been created before, then that exact same scheme should be
    returned. Otherwise, a new scheme should be generated with those parameters.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    new_dgk_1 = DGK.from_security_parameter(10, 100, 11)
    new_dgk_1.save_globally()
    new_dgk_2: DGK = DGK.from_id(new_dgk_1.identifier)
    new_dgk_3 = DGK.from_security_parameter(10, 100, 11)

    new_dgk_1.shut_down()
    new_dgk_2.shut_down()
    new_dgk_3.shut_down()
    scheme.shut_down()

    assert new_dgk_1 is new_dgk_2
    assert new_dgk_1 is not new_dgk_3
    assert new_dgk_2 is not new_dgk_3
    assert new_dgk_1 != new_dgk_3
    assert new_dgk_2 != new_dgk_3


async def send_and_receive(pools: Tuple[Pool, Pool], obj: Any) -> Any:
    """
    Method that sends objects from one party to another.

    :param pools: collection of communication pools
    :param obj: object to be sent
    :return: the received object
    """
    # send from host 1 to host 2
    await pools[0].send("local1", obj)
    item = await pools[1].recv("local0")
    return item


@pytest.mark.asyncio
@pytest.mark.parametrize("with_precision", (True, False))
async def test_sending_and_receiving(
    pool_http_2p: Tuple[Pool, Pool], with_precision: bool
) -> None:
    """
    This test ensures that serialisation logic is correctly loading into the communication module.

    :param pool_http_2p: collection of communication pools
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme_prime = await send_and_receive(pool_http_2p, scheme)
    assert DGK.from_id(scheme.identifier) is scheme
    assert scheme_prime is scheme
    # the scheme has been sent once, so the httpclients should be in the scheme's client
    # history.
    assert len(scheme.client_history) == 2
    assert scheme.client_history[0] == pool_http_2p[0].pool_handlers["local1"]
    assert scheme.client_history[1] == pool_http_2p[1].pool_handlers["local0"]

    encryption = scheme.encrypt(plaintext=4)
    encryption_prime = await send_and_receive(pool_http_2p, encryption)
    encryption_prime.scheme.shut_down()
    assert encryption == encryption_prime

    public_key_prime = await send_and_receive(pool_http_2p, scheme.public_key)
    assert scheme.public_key == public_key_prime

    secret_key_prime = await send_and_receive(pool_http_2p, scheme.secret_key)
    assert scheme.secret_key == secret_key_prime


@pytest.mark.asyncio
@pytest.mark.parametrize("with_precision", (True, False))
async def test_broadcasting(
    pool_http_3p: Tuple[Pool, Pool, Pool], with_precision: bool
) -> None:
    """
    This test ensures that broadcasting ciphertexts works as expected.

    :param pool_http_3p: collection of communication pools
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    await asyncio.gather(
        *(
            pool_http_3p[0].send("local1", scheme),
            pool_http_3p[0].send("local2", scheme),
        )
    )
    scheme_prime_1, scheme_prime_2 = await asyncio.gather(
        *(pool_http_3p[1].recv("local0"), pool_http_3p[2].recv("local0"))
    )
    assert DGK.from_id(scheme.identifier) is scheme
    assert scheme_prime_1 is scheme
    assert scheme_prime_2 is scheme
    # the scheme has been sent once to each party, so the httpclients should be in the scheme's client
    # history.
    assert len(scheme.client_history) == 3
    assert pool_http_3p[0].pool_handlers["local1"] in scheme.client_history
    assert pool_http_3p[0].pool_handlers["local2"] in scheme.client_history
    assert pool_http_3p[1].pool_handlers["local0"] in scheme.client_history
    assert pool_http_3p[2].pool_handlers["local0"] in scheme.client_history

    encryption = scheme.encrypt(plaintext=4)
    await pool_http_3p[0].broadcast(encryption, "msg_id")
    encryption_prime_1, encryption_prime_2 = await asyncio.gather(
        *(
            pool_http_3p[1].recv("local0", "msg_id"),
            pool_http_3p[2].recv("local0", "msg_id"),
        )
    )

    encryption_prime_1.scheme.shut_down()

    assert encryption == encryption_prime_1
    assert encryption == encryption_prime_2


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_randomization(with_precision: bool) -> None:
    """
    Test to determine whether the DGK ciphertext serialization works properly.
    Test to determine whether the DGK ciphertext serialization correctly randomizes non-fresh
    ciphertexts.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    ciphertext = scheme.unsafe_encrypt(1)
    val_non_randomized = ciphertext.peek_value()
    with pytest.warns(EncryptionSchemeWarning, match=WARN_UNFRESH_SERIALIZATION):
        ciphertext.serialize()
    val_randomized = ciphertext.peek_value()
    scheme.shut_down()
    assert val_non_randomized != val_randomized
    assert not ciphertext.fresh


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_fresh_ciphertext(with_precision: bool) -> None:
    """
    Test to determine whether the DGK ciphertext serialization works properly for fresh
    ciphertexts.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = dgk_scheme(with_precision)
    scheme.boot_generation()
    ciphertext = scheme.encrypt(1)

    assert ciphertext.fresh

    ciphertext_prime = DGKCiphertext.deserialize(ciphertext.serialize())

    assert not ciphertext.fresh
    assert not ciphertext_prime.fresh

    scheme.shut_down()
    assert ciphertext == ciphertext_prime
