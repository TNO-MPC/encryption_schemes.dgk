"""
Implementation of the Asymmetric Encryption Scheme known as DGK.
"""

from __future__ import annotations

import secrets
import warnings
from queue import Queue  # pylint: disable=unused-import
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, cast

from typing_extensions import TypedDict, get_args

from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import (
    AsymmetricEncryptionScheme,
    PublicKey,
    SecretKey,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncodedPlaintext,
    EncryptionSchemeWarning,
)
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    RandomizableCiphertext,
    RandomizedEncryptionScheme,
)
from tno.mpc.encryption_schemes.utils import (
    FixedPoint,
    is_prime,
    mod_inv,
    pow_mod,
    randprime,
)
from tno.mpc.encryption_schemes.utils.utils import extended_euclidean

# Check to see if the communication module is available
try:
    from tno.mpc.communication import RepetitionError, Serialization
    from tno.mpc.communication.httphandlers import HTTPClient

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False

fxp = FixedPoint.fxp


WARN_INEFFICIENT_HOM_OPERATION = (
    "Identified a fresh ciphertext as input to a homomorphic operation, which is no longer fresh "
    "after the operation. This indicates a potential inefficiency if the non-fresh input may also "
    "used in other operations (unused randomness). Solution: randomize ciphertexts as late as "
    "possible, e.g. by encrypting them with scheme.unsafe_encrypt and randomizing them just before "
    "sending. Note that the serializer randomizes non-fresh ciphertexts by default."
)

WARN_UNFRESH_SERIALIZATION = (
    "Serializer identified and rerandomized a non-fresh ciphertext."
)


class SerializationError(Exception):
    """
    Communication error for DGK.
    """

    def __init__(self) -> None:
        super().__init__(
            "The tno.mpc.communication package has not been installed. "
            "Please install this package before you call the serialisation code."
        )


class DGKPublicKey(PublicKey):
    """
    PublicKey for the DGK encryption scheme.
    """

    def __init__(self, g: int, h: int, u: int, n: int, t: int):
        r"""
        Constructs a new DGK public key.

        :param g: Generator of order $v_p \cdot v_q \cdot u \mod n$
        :param h: Generator of the invertible elements modulo n of order $v_p \cdot v_q$
        :param u: Modulus of the plaintext space.
        :param n: Modulus of the ciphertext space.
        :param t: The number of bits $t$ of $v_p$ and $v_q$.
        """
        super().__init__()

        self.g = g
        self.h = h
        self.u = u
        self.n = n
        self.t = t

    def __hash__(self) -> int:
        """
        Compute a hash from this DGKPublicKey instance.

        :return: Hash value.
        """
        return hash((self.g, self.h, self.u, self.n, self.t))

    def __eq__(self, other: object) -> bool:
        """
        Compare this DGKPublicKey with another to determine (in)equality.

        :param other: Object to compare this DGKPublicKey with.
        :raise TypeError: When other object is not a DGKPublicKey.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, DGKPublicKey):
            raise TypeError(
                f"Expected comparison with another DGKPublicKey, not {type(other)}"
            )
        return (
            self.g == other.g
            and self.h == other.h
            and self.u == other.u
            and self.n == other.n
            and self.t == other.t
        )

    # region Serialization logic

    class SerializedDGKPublicKey(TypedDict):
        g: int
        h: int
        u: int
        n: int
        t: int

    def serialize(self, **_kwargs: Any) -> DGKPublicKey.SerializedDGKPublicKey:
        r"""
        Serialization function for public keys, which will be passed to the communication module.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGKPublicKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "g": self.g,
            "h": self.h,
            "u": self.u,
            "n": self.n,
            "t": self.t,
        }

    @staticmethod
    def deserialize(
        obj: DGKPublicKey.SerializedDGKPublicKey, **_kwargs: Any
    ) -> DGKPublicKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: serialized version of a DGKPublicKey.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized DGKPublicKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return DGKPublicKey(
            g=obj["g"],
            h=obj["h"],
            u=obj["u"],
            n=obj["n"],
            t=obj["t"],
        )

    # endregion


class DGKSecretKey(SecretKey):
    """
    SecretKey for the DGK encryption scheme.
    """

    def __init__(self, v_p: int, v_q: int, p: int, q: int):
        """
        Constructs a new DGK secret key.

        :param v_p: Prime number used during decryption
        :param v_q: Prime number used during decryption
        :param p: Prime factor of modulus $n$
        :param q: Prime factor of modulus $n$
        """
        super().__init__()

        self.v_p = v_p
        self.v_q = v_q
        self.p = p
        self.q = q

        self.v_p_v_q = self.v_p * self.v_q

    def __hash__(self) -> int:
        """
        Compute a hash from this DGKSecretKey instance.

        :return: Hash value.
        """
        return hash((self.v_p, self.v_q, self.p, self.q))

    def __eq__(self, other: object) -> bool:
        """
        Compare this DGKSecretKey with another to determine (in)equality.

        :param other: Object to compare this DGKSecretKey with.
        :raise TypeError: When other object is not a DGKSecretKey.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, DGKSecretKey):
            raise TypeError(
                f"Expected comparison with another DGKSecretKey, not {type(other)}"
            )
        return (
            self.v_p == other.v_p
            and self.v_q == other.v_q
            and self.p == other.p
            and self.q == other.q
        )

    # region Serialization logic

    class SerializedDGKSecretKey(TypedDict):
        v_p: int
        v_q: int
        p: int
        q: int

    def serialize(self, **_kwargs: Any) -> DGKSecretKey.SerializedDGKSecretKey:
        r"""
        Serialization function for secret keys, which will be passed to the communication module.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGKSecretKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "v_p": self.v_p,
            "v_q": self.v_q,
            "p": self.p,
            "q": self.q,
        }

    @staticmethod
    def deserialize(
        obj: DGKSecretKey.SerializedDGKSecretKey, **_kwargs: Any
    ) -> DGKSecretKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module

        :param obj: serialized version of a DGKSecretKey.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized DGKSecretKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return DGKSecretKey(
            v_p=obj["v_p"],
            v_q=obj["v_q"],
            p=obj["p"],
            q=obj["q"],
        )

    # endregion


KeyMaterial = Tuple[DGKPublicKey, DGKSecretKey]
Plaintext = Union[int, float, FixedPoint]


class DGKCiphertext(RandomizableCiphertext[KeyMaterial, Plaintext, int, int]):
    """
    Ciphertext for the DGK asymmetric encryption scheme. This ciphertext is rerandomizable
    and supports homomorphic operations.
    """

    scheme: DGK  # type: ignore[assignment]

    def __init__(self, raw_value: int, scheme: DGK, *, fresh: bool = False):
        """
        Construct a RandomizableCiphertext, with the given value for the given EncryptionScheme.

        :param raw_value: DGKCiphertext value.
        :param scheme: DGK scheme that is used to encrypt this ciphertext.
        :param fresh: Indicates whether fresh randomness is already applied to the raw_value.
        :raise TypeError: If the given scheme is not of the type DGK.
        """

        if not isinstance(scheme, DGK):
            raise TypeError(f"expected DGK scheme, got {type(scheme)}")
        super().__init__(raw_value, scheme, fresh=fresh)

    def apply_randomness(self: DGKCiphertext, randomization_value: int) -> None:
        """
        Rerandomize this ciphertext using the given random value.

        :param randomization_value: Random value used for rerandomization.
        """
        modulus = self.scheme.public_key.n
        self._raw_value *= randomization_value
        self._raw_value %= modulus

    def is_zero(self: DGKCiphertext) -> bool:
        """
        Determine if the underlying plaintext of this ciphertext equals 0, without doing a full decryption.

        :return: True if plaintext is 0, False otherwise.
        """
        return self.scheme.is_zero(self)

    def __eq__(self, other: object) -> bool:
        """
        Compare this DGKCiphertext with another to determine (in)equality.

        :param other: Object to compare this DGKCiphertext with.
        :raise TypeError: When other object is not a DGKCiphertext.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, DGKCiphertext):
            raise TypeError(
                f"Expected comparison with another DGKCiphertext, not {type(other)}"
            )
        return self._raw_value == other._raw_value and self.scheme == other.scheme

    def copy(self: DGKCiphertext) -> DGKCiphertext:
        """
        Create a copy of this Ciphertext, with the same value and scheme. The copy is not
        randomized and is considered not fresh.

        :return: Copied DGKCiphertext.
        """
        return DGKCiphertext(raw_value=self._raw_value, scheme=self.scheme)

    # region Serialization logic

    class SerializedDGKCiphertext(TypedDict):
        value: int
        scheme: DGK

    def serialize(self, **_kwargs: Any) -> DGKCiphertext.SerializedDGKCiphertext:
        r"""
        Serialization function for DGK ciphertexts, which will be passed to the communication
        module.

        If the ciphertext is not fresh, it is randomized before serialization. After serialization,
        it is always marked as not fresh for security reasons.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGKCiphertext.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if not self.fresh:
            warnings.warn(WARN_UNFRESH_SERIALIZATION, EncryptionSchemeWarning)
            self.randomize()
        self._fresh = False
        return {
            "value": self._raw_value,
            "scheme": self.scheme,
        }

    @staticmethod
    def deserialize(
        obj: DGKCiphertext.SerializedDGKCiphertext, **_kwargs: Any
    ) -> DGKCiphertext:
        r"""
        Deserialization function for DGK ciphertexts, which will be passed to the
        communication module.

        :param obj: serialized version of a DGKCiphertext.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized DGKCiphertext from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return DGKCiphertext(
            raw_value=obj["value"],
            scheme=obj["scheme"],
        )

    # endregion


class DGK(
    AsymmetricEncryptionScheme[
        KeyMaterial,
        Plaintext,
        int,
        int,
        DGKCiphertext,
        DGKPublicKey,
        DGKSecretKey,
    ],
    RandomizedEncryptionScheme[KeyMaterial, Plaintext, int, int, DGKCiphertext],
):
    """
    DGK Encryption Scheme. This is an AsymmetricEncryptionScheme, with a public and secret key.
    This is also a RandomizedEncryptionScheme, thus having internal randomness generation and
    allowing for the use of precomputed randomness.
    """

    public_key: DGKPublicKey
    secret_key: DGKSecretKey

    def __init__(
        self,
        public_key: DGKPublicKey,
        secret_key: Optional[DGKSecretKey],
        precision: int = 0,
        full_decryption: bool = True,
        share_secret_key: bool = False,
        randomizations: Optional["Queue[int]"] = None,
        max_size: int = 100,
        total: Optional[int] = None,
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ):
        """
        Construct a new DGK encryption scheme, with the given keypair, randomness object,
        precision for floating point encryption.

        :param public_key: Public key for this DGK Scheme.
        :param secret_key: Optional Secret Key for this DGK Scheme (None when unknown).
        :param precision: Floating point precision of this encoding (Default: 0), in decimal places.
        :param full_decryption: Boolean value stating whether full decryptions should be possible. If True, a
            decryption lookup table will be constructed. If False, only checking for 0 is possible.
        :param share_secret_key: Boolean value stating whether the secret key should be
            included in serialization. This should only be set to True if one is really sure of it.
            (Default: False)
        :param randomizations: queue with randomizations. If no queue is given, it creates a
            fresh one. (Default: None)
        :param max_size: maximum size of the queue. (Default: 100)
        :param total: upper bound on the total amount of randomizations to generate. (Default: None)
        :param nr_of_threads: number of generation worker threads that should be started.
            (Default: 1)
        :param path: path (including filename) to the file that contains randomizations.
            By default no path is given and no randomness is extracted from any files. (Default: "")
        :param separator: separator for the random values in the given file. (Default: ",")
        :param start_generation: flag that determines whether the scheme starts generating
            randomness immediately. (Default: True)
        :param debug: flag to determine whether debug information should be displayed.
            (Default: False)
        """
        AsymmetricEncryptionScheme.__init__(
            self, public_key=public_key, secret_key=secret_key
        )
        RandomizedEncryptionScheme.__init__(
            self,
            randomizations=randomizations,
            max_size=max_size,
            total=total,
            nr_of_threads=nr_of_threads,
            path=path,
            separator=separator,
            start_generation=start_generation,
            debug=debug,
        )

        self.precision = precision
        self.max_value = public_key.u // (2 * 10**precision)
        self.min_value = -(public_key.u - (public_key.u // 2 + 1)) // 10**precision

        # Variable that determines whether a secret key is sent when the scheme is sent
        # over a communication channel
        self.share_secret_key = share_secret_key

        # Create decryption table
        self.decryption_table: Optional[Dict[int, int]] = None
        if secret_key is not None and full_decryption:
            self.decryption_table = DGK._create_decryption_table(public_key, secret_key)

        self.client_history: List[HTTPClient] = []

    @staticmethod
    def _create_decryption_table(
        public_key: DGKPublicKey, secret_key: DGKSecretKey
    ) -> Dict[int, int]:
        """
        Create decryption table given the public and secret key.

        :param public_key: DGK public key.
        :param secret_key: DGK secret key.
        :return: Decryption table
        """
        decryption_table = {}
        g_pow_v_p = pow_mod(public_key.g, secret_key.v_p, secret_key.p)
        for plaintext in range(0, public_key.u):
            decryption_table[pow_mod(g_pow_v_p, plaintext, secret_key.p)] = plaintext
        return decryption_table

    def get_message_from_value(self, value: int) -> int:
        """
        Get the message from the aux value based on an encrypted value

        :param value: Encrypted value
        :raise ValueError: In case no original message exists in the aux table for this value, or if full decryptions
            are not supported.
        :return: Decrypted message
        """
        if self.decryption_table is None:
            raise ValueError(
                "No full decryption can be performed. "
                "Use 'is_zero' if only checking equality to 0 is needed. "
                "Otherwise, instantiate the scheme with 'full_decryption' set to True."
            )
        decryption = self.decryption_table.get(value)
        if decryption is not None:
            return decryption
        raise ValueError("This value could not be decrypted.")

    @staticmethod
    def get_prime(bits: int) -> int:
        """
        Get a random prime with the given bit size

        :param bits: Amount of bits of the prime
        :return: Prime number
        """
        return randprime(2 ** (bits - 1), 2**bits)

    @staticmethod
    def get_cyclic_generator(modulus: int, prime_factors: Iterable[int]) -> int:
        r"""
        Given a cylic group with the given modulus, that has order modulus - 1. This function obtains a random generator
        of this cyclic group.
        I.e. the output is the generator of $\mathbb{Z}_p^*$ with the modulus $p$ prime. The order of the group equals
        $p - 1$ and its prime factors are given.

        This is based on Algorithm 4.80 of 'Handbook of Applied Cryptography' by Menzes, Oorschot, and Vanstone.

        :param modulus: Prime modulus of the cyclic group.
        :param prime_factors: Prime factors of modulus - 1.
        :return: Generator of $\mathbb{Z}_p^*$.
        """
        while True:
            generator = secrets.randbelow(modulus - 1) + 1
            if all(
                map(
                    lambda factor: pow_mod(generator, (modulus - 1) // factor, modulus)
                    != 1,
                    prime_factors,
                )
            ):
                return generator

    @staticmethod
    def get_composite_generator(
        p: int,
        q: int,
        p_min_1_prime_factors: Iterable[int],
        q_min_1_prime_factors: Iterable[int],
    ) -> int:
        r"""
        Sample a random generator of the non-cyclic group $\mathbb{Z}_n^*$, with $n=p\cdot q$, and $p$, $q$ prime of
        maximum order $\text{lcm}(p - 1, q - 1)$. This algorithm requires the primes $p$ and $q$ and the prime factors
        of $p - 1$ and $q - 1$.

        This is based on Algorithm 4.83 of 'Handbook of Applied Cryptography' by Menzes, Oorschot, and Vanstone.

        :param p: First prime factor of the group modulus $n=p\cdot q$.
        :param q: Second prime factor of the group modulus $n=p\cdot q$.
        :param p_min_1_prime_factors: Prime factors of $p - 1$.
        :param q_min_1_prime_factors: Prime factors of $q - 1$.
        :return: Generator of maximum order $\text{lcm}(p - 1, q - 1)$ from $\mathbb{Z}^*_n$.
        """
        generator_z_p = DGK.get_cyclic_generator(p, p_min_1_prime_factors)
        generator_z_q = DGK.get_cyclic_generator(q, q_min_1_prime_factors)
        _gcd, bezout_coeff_p, bezout_coeff_q = extended_euclidean(p, q)
        # _gcd is 1, since p and q are both prime
        return (
            generator_z_p * q * bezout_coeff_q + generator_z_q * p * bezout_coeff_p
        ) % (p * q)

    @staticmethod
    def generate_key_material(  # type: ignore[override]
        v_bits: int,
        n_bits: int,
        u: int,
    ) -> KeyMaterial:
        r"""
        Method to generate key material (DGKPublicKey and DGKPrivateKey).

        :param v_bits: Bit length $t$ of the private key values $v_p$ and $v_q$
        :param n_bits: Bit length of the public key RSA modulus $n$
        :param u: Bit length of the message space
        :raise ValueError:  In case $u$ is not a prime number
        :return: Tuple with first the Public Key and then the Secret Key.
        """
        if not is_prime(u):
            raise ValueError("u is not a prime")

        # Construct n = p * q, with p, q prime
        while True:
            # Construct primes v_p, v_q, p, and q such that v_p | (p - 1), v_q | (q - 1), u | (p - 1), and q | (p - 1).
            # But not v_p | (q - 1) and not v_q | (p - 1).

            # First generate v_p and v_q, both with v_bits length.
            v_p = DGK.get_prime(v_bits)
            while True:
                v_q = DGK.get_prime(v_bits)
                # Ensure unique factors v_p and v_q
                if v_q != v_p:
                    break

            # Ensure that v_p | (p - 1), v_q | (q - 1), u | (p - 1), and q | (p - 1)
            p_base = 2 * u * v_p
            q_base = 2 * u * v_q

            # Check that n_bits is sufficient such that p and q can exist
            if n_bits - p_base.bit_length() - q_base.bit_length() < 4:
                raise ValueError(
                    f"n_bits is too small, it should be at least {4 + p_base.bit_length() + q_base.bit_length()}"
                )

            # Construct p
            # 2*u*v_p*p_r = p − 1, with p_r a random prime
            while True:
                p_random = DGK.get_prime(n_bits // 2 - p_base.bit_length() + 1)
                p = p_base * p_random + 1
                if is_prime(p):
                    break

            # Construct q
            # 2*u*v_q*q_r = q − 1, with q_r a random prime
            while True:
                q_random = DGK.get_prime(n_bits // 2 - q_base.bit_length() + 1)
                # ensure unique prime factors of q - 1 and p - 1
                if q_random == p_random:
                    continue
                q = q_base * q_random + 1
                if is_prime(q):
                    break

            # Ensure that not v_p | (q - 1) and not v_q | (p - 1)
            if (q - 1) % v_p == 0 or (p - 1) % v_q == 0:
                continue

            # Create RSA modulus n
            n = p * q

            if n.bit_length() == n_bits:
                break

        # We know the prime factors of (p - 1) and (q - 1)
        p_min_1_prime_factors = (2, u, v_p, p_random)
        q_min_1_prime_factors = (2, u, v_q, q_random)

        # Construct random generators g, h in Z_n^*, such that g has order u * v_p * v_q and h has order v_p * v_q.
        g = DGK.get_composite_generator(
            p, q, p_min_1_prime_factors, q_min_1_prime_factors
        )
        while True:
            h = DGK.get_composite_generator(
                p, q, p_min_1_prime_factors, q_min_1_prime_factors
            )
            if g != h:
                break
        # g and h now both have order  2 * p_random * q_random * v_p * v_q * u
        remove_order_factors = 2 * p_random * q_random
        g = pow_mod(g, remove_order_factors, n)  # make g of order v_p * v_q * u
        h = pow_mod(h, remove_order_factors * u, n)  # make h of order v_p * v_q
        return DGKPublicKey(g, h, u, n, v_bits), DGKSecretKey(v_p, v_q, p, q)

    def encode(self, plaintext: Plaintext) -> EncodedPlaintext[int]:
        """
        Encode a float or int with the given precision of this instantiation. Allows for positive
        and negative numbers.

        :param plaintext: Plaintext to be encoded.
        :raise ValueError: If the plaintext is outside the supported range of this DGK
            instance.
        :return: EncodedPlaintext object containing the encoded value.
        """
        if not self.min_value <= plaintext <= self.max_value:
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}], {plaintext} is outside that range."
            )
        plaintext_fxp = fxp(plaintext, self.precision)
        return EncodedPlaintext(plaintext_fxp.value, self)

    def decode(self, encoded_plaintext: EncodedPlaintext[int]) -> Plaintext:
        """
        Decode an EncodedPlaintext given the specified precision of this instantiation.

        :param encoded_plaintext: Plaintext to be decoded.
        :return: decoded Plaintext value
        """
        value = (
            encoded_plaintext.value
            if 2 * encoded_plaintext.value <= self.public_key.u
            else encoded_plaintext.value - self.public_key.u
        )
        return FixedPoint(value, self.precision)

    def _unsafe_encrypt_raw(
        self,
        plaintext: EncodedPlaintext[int],
    ) -> DGKCiphertext:
        r"""
        Encrypts an encoded (raw) plaintext value, but does not apply randomization. Given a raw plaintext message
        $m \in \mathbb{Z}_u$, we compute the ciphertext value as $c = g^m \mod n$.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Non-randomized DGKCiphertext object containing the encrypted plaintext.
        """
        return DGKCiphertext(
            pow_mod(self.public_key.g, plaintext.value, self.public_key.n), self
        )

    def _decrypt_raw(self, ciphertext: DGKCiphertext) -> EncodedPlaintext[int]:
        """
        Decrypts a ciphertext to its encoded plaintext value.

        :param ciphertext: DGKCiphertext object containing the ciphertext to be decrypted.
        :return: EncodedPlaintext object containing the encoded decryption of the ciphertext.
        :raise ValueError: If full decryptions are not possible.
        """
        if self.decryption_table is None:
            raise ValueError(
                "No full decryption can be performed. "
                "Use 'is_zero' if only checking equality to 0 is needed. "
                "Otherwise, instantiate the scheme with 'full_decryption' set to True."
            )
        value = pow_mod(ciphertext.peek_value(), self.secret_key.v_p, self.secret_key.p)
        value = self.get_message_from_value(value)
        return EncodedPlaintext(value, self)

    def is_zero(self, ciphertext: DGKCiphertext) -> bool:
        """
        Determine if the underlying plaintext of a ciphertext equals 0, without doing a full decryption.

        :param ciphertext: DGKCiphertext object containing the ciphertext to be checked.
        :return: True if plaintext is 0, False otherwise.
        """
        return (
            pow_mod(ciphertext.peek_value(), self.secret_key.v_p_v_q, self.secret_key.p)
            == 1
        )

    def neg(self, ciphertext: DGKCiphertext) -> DGKCiphertext:
        """
        Negate the underlying plaintext of this ciphertext. I.e. if the original plaintext of
        this ciphertext was 5. this method returns the ciphertext that has -5 as underlying
        plaintext.

        The resulting ciphertext is fresh only if the input was fresh. The input is marked as non-fresh after the
        operation.

        :param ciphertext: DGKCiphertext of which the underlying plaintext should be negated.
        :return: DGKCiphertext object corresponding to the negated plaintext.
        """
        new_ciphertext_fresh = ciphertext.fresh
        if new_ciphertext_fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return DGKCiphertext(
            mod_inv(ciphertext.get_value(), self.public_key.n),
            self,
            fresh=new_ciphertext_fresh,
        )

    def add(
        self,
        ciphertext_1: DGKCiphertext,
        ciphertext_2: Union[DGKCiphertext, Plaintext],
    ) -> DGKCiphertext:
        """
        Add the underlying plaintext value of ciphertext_1 with the underlying plaintext value of
        ciphertext_2.

        The resulting ciphertext is fresh only if at least one of the inputs was fresh. Both inputs
        are marked as non-fresh after the operation.

        :param ciphertext_1: First DGKCiphertext of which the underlying plaintext is added.
        :param ciphertext_2: Second DGKCiphertext of which the underlying plaintext is
            added to the first.
        :raise AttributeError: When ciphertext_2 does not have the same public key as ciphertext_1.
        :return: A DGKCiphertext containing the encryption of the addition of both values.
        """
        if isinstance(ciphertext_2, get_args(Plaintext)):
            ciphertext_2 = self.unsafe_encrypt(cast(Plaintext, ciphertext_2))
        elif ciphertext_1.scheme != cast(DGKCiphertext, ciphertext_2).scheme:
            raise AttributeError(
                "The public key of your first ciphertext is not equal to the "
                "public key of your second ciphertext."
            )
        ciphertext_2 = cast(DGKCiphertext, ciphertext_2)

        new_ciphertext_fresh = ciphertext_1.fresh or ciphertext_2.fresh
        if new_ciphertext_fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return DGKCiphertext(
            ciphertext_1.get_value() * ciphertext_2.get_value() % self.public_key.n,
            self,
            fresh=new_ciphertext_fresh,
        )

    def mul(self, ciphertext: DGKCiphertext, scalar: int) -> DGKCiphertext:  # type: ignore[override]  # pylint: disable=arguments-renamed
        """
        Multiply the underlying plaintext value of ciphertext with the given scalar.

        The resulting ciphertext is fresh only if the input was fresh. The input is marked as
        non-fresh after the operation.

        :param ciphertext: DGKCiphertext of which the underlying plaintext is multiplied.
        :param scalar: A scalar with which the plaintext underlying ciphertext should be
            multiplied.
        :raise TypeError: When the scalar is not an integer.
        :return: DGKCiphertext containing the encryption of the product of both values.
        """
        if not isinstance(scalar, int):
            raise TypeError(
                f"Type of  scalar (second multiplicand) should be an integer and not"
                f" {type(scalar)}."
            )
        if scalar < 0:
            ciphertext = self.neg(ciphertext)
            scalar = -scalar

        new_ciphertext_fresh = ciphertext.fresh
        if new_ciphertext_fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        return DGKCiphertext(
            pow(ciphertext.get_value(), scalar, self.public_key.n),
            self,
            fresh=new_ciphertext_fresh,
        )

    def __eq__(self, other: object) -> bool:
        """
        Compare this DGK scheme with another to determine (in)equality. Does not take the
        secret key into account as it might not be known and the public key combined with the
        precision should be sufficient to determine equality.

        :param other: Object to compare this DGK scheme with.
        :return: Boolean value representing (in)equality of both objects.
        """
        # Equality should still hold if the secret key is not available
        return (
            isinstance(other, DGK)
            and self.precision == other.precision
            and self.public_key == other.public_key
        )

    def generate_randomness(self) -> int:
        """
        Method to generate randomness for DGK.

        :return: A random number.
        """
        # sample 2.5t random bits
        random_element = (
            secrets.randbelow((1 << int(2.5 * (self.public_key.t + 1))) - 1) + 1
        )
        return pow_mod(self.public_key.h, random_element, self.public_key.n)

    @classmethod
    def id_from_arguments(  # type: ignore[override]
        cls,
        public_key: DGKPublicKey,
        precision: int = 0,
    ) -> int:
        """
        Method that turns the arguments for the constructor into an identifier. This identifier is
        used to find constructor calls that would result in identical schemes.

        :param public_key: DGKPublicKey of the DGK instance.
        :param precision: Precision of the DGK instance
        :return: Identifier of the DGK instance
        """
        return hash((public_key, precision))

    # region Serialization logic

    class SerializedDGK(TypedDict, total=False):
        scheme_id: int
        prec: int
        pubkey: DGKPublicKey
        seckey: DGKSecretKey

    def serialize(
        self,
        *,
        destination: Optional[Union[HTTPClient, List[HTTPClient]]] = None,
        **_kwargs: Any,
    ) -> DGK.SerializedDGK:
        r"""
        Serialization function for DGK schemes, which will be passed to the communication
        module. The sharing of the secret key depends on the attribute share_secret_key.

        :param destination: HTTPClient representing where the message will go if applicable, can also be a list of
            clients in case of a broadcast message.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGk scheme.
        """
        if isinstance(destination, HTTPClient):
            destination = [destination]
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if self.identifier not in self._instances:
            self.save_globally()
        if destination is not None and all(
            d in self.client_history for d in destination
        ):
            return {
                "scheme_id": self.identifier,
            }
        if destination is not None:
            for dest in destination:
                if dest not in self.client_history:
                    self.client_history.append(dest)
        if self.share_secret_key:
            return self.serialize_with_secret_key()
        return self.serialize_without_secret_key()

    def serialize_with_secret_key(
        self,
    ) -> DGK.SerializedDGK:
        """
        Serialization function for DGK schemes, that does include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGK scheme.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": self.precision,
            "pubkey": self.public_key,
            "seckey": self.secret_key,
        }

    def serialize_without_secret_key(self) -> DGK.SerializedDGK:
        """
        Serialization function for DGK schemes, that does not include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this DGK scheme (without the secret key).
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": self.precision,
            "pubkey": self.public_key,
        }

    @staticmethod
    def deserialize(
        obj: DGK.SerializedDGK,
        *,
        origin: Optional[HTTPClient] = None,
        **_kwargs: Any,
    ) -> DGK:
        r"""
        Deserialization function for DGK schemes, which will be passed to
        the communication module

        :param obj: serialized version of a DGK scheme.
        :param origin: HTTPClient representing where the message came from if applicable
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :raise ValueError: When the received scheme is received incorrectly.
        :return: Deserialized DGK scheme from the given dict. Might not have a secret
        :return: Deserialized DGK scheme from the given dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if "scheme_id" in obj:
            identifier = obj["scheme_id"]
            dgk: DGK = DGK.from_id(identifier)
            if origin is None:
                raise ValueError(
                    f"The scheme was sent through an ID, but the origin is {origin}"
                )
            if origin not in dgk.client_history:
                raise ValueError(
                    f"The scheme was sent through an ID by {origin.addr}:{origin.port}, "
                    f"but this scheme was never"
                    "communicated with this party"
                )
        else:
            pubkey = obj["pubkey"]
            precision = obj["prec"]
            # This piece of code is specifically used for the case where sending and receiving
            # happens between hosts running the same python instance (local network).
            # In this case, the DGK scheme that was sent is already available before it
            # arrives and does not need to be created anymore.
            identifier = DGK.id_from_arguments(public_key=pubkey, precision=precision)
            if identifier in DGK._instances:
                dgk = DGK.from_id(identifier)
            else:
                dgk = DGK(
                    public_key=pubkey,
                    secret_key=obj["seckey"] if "seckey" in obj else None,
                    precision=precision,
                    nr_of_threads=0,
                    start_generation=False,
                )
                dgk.save_globally()
        if origin is not None and origin not in dgk.client_history:
            dgk.client_history.append(origin)
        return dgk

    # endregion


if COMMUNICATION_INSTALLED:
    try:
        Serialization.register_class(DGK)
        Serialization.register_class(DGKCiphertext)
        Serialization.register_class(DGKPublicKey)
        Serialization.register_class(DGKSecretKey)
    except RepetitionError:
        pass
