# TNO PET Lab - secure Multi-Party Computation (MPC) - Encryption Schemes - DGK

Implementation of the DGK encryption scheme. With support with precomputation of randomness. The
encryption scheme supports positive and negative numbers, as well as fixed point encoding of
numbers. Homomorphic addition of ciphertexts, negation of ciphertexts, and multiplication of
ciphertexts with integral scalars has been included as well.

The TNO PET Lab consists of generic software components, procedures, and
functionalities developed and maintained on a regular basis to facilitate and
aid in the development of PET solutions. The lab is a cross-project initiative
allowing us to integrate and reuse previously developed PET functionalities to
boost the development of new protocols and solutions.

### PET Lab

The TNO PET Lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of PET solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed PET functionalities to boost the development of new protocols and solutions.

The package `tno.mpc.encryption_schemes.dgk` is part of the [TNO Python Toolbox](https://github.com/TNO-PET).

_Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws._  
_This implementation of cryptographic software has not been audited. Use at your own risk._

## Documentation

Documentation of the `tno.mpc.encryption_schemes.dgk` package can be found
[here](https://docs.pet.tno.nl/mpc/encryption_schemes/dgk/3.0.5).

## Install

Easily install the `tno.mpc.encryption_schemes.dgk` package using `pip`:

```console
$ python -m pip install tno.mpc.encryption_schemes.dgk
```

_Note:_ If you are cloning the repository and wish to edit the source code, be
sure to install the package in editable mode:

```console
$ python -m pip install -e 'tno.mpc.encryption_schemes.dgk'
```

If you wish to run the tests you can use:

```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[tests]'
```

If you wish to use the tno.mpc.communication module you can use:

```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[communication]'
```

_Note:_ A significant performance improvement can be achieved by installing the
GMPY2 library.

```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[gmpy]'
```

## Basic Usage

The DGK scheme can be used with and without support for full decryptions. When
full decryptions are not supported one can only use the private key to determine
whether a ciphertext is zero or not.

Full decryption support requires the scheme to pre-compute and store a lookup
table for all possible plaintexts. This table can become impractically large
when the plaintext space is big.

Below we list usage examples in both cases.

Basic usage (with full decryption):

```python
from tno.mpc.encryption_schemes.dgk import DGK

if __name__ == "__main__":
    # initialize DGK (with full decryption support) with v_p and v_q of length t=160 bits, n of length 1000 bits.
    # The message space contains 10009 values and the precision of this scheme is 1 decimal
    dgk_scheme = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1)
    # encrypt the number 8.1
    ciphertext1 = dgk_scheme.encrypt(8.1)
    # add 0.9 to the original plaintext
    ciphertext1 += 0.9
    # multiply the original plaintext by 10
    ciphertext1 *= 10
    # encrypt the number 10
    ciphertext2 = dgk_scheme.encrypt(10)
    # add both encrypted numbers together
    encrypted_sum = ciphertext1 + ciphertext2
    # ...communication...
    # decrypt the encrypted sum to 100
    decrypted_sum = dgk_scheme.decrypt(encrypted_sum)
    assert decrypted_sum == 100
```

Usage (without full decryption)

```python
from tno.mpc.encryption_schemes.dgk import DGK

if __name__ == "__main__":
    # initialize DGK (without full decryption support) with v_p and v_q of length t=160 bits, n of length 2048 bits.
    # The message space contains 10009 values and the precision of this scheme is 1 decimal
    dgk_scheme = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1, full_decryption=False)
    # encrypt the number 8.1
    ciphertext1 = dgk_scheme.encrypt(8.1)
    # add 0.9 to the original plaintext
    ciphertext1 += 0.9
    # multiply the original plaintext by 10
    ciphertext1 *= 10
    # encrypt the number 10
    ciphertext2 = dgk_scheme.encrypt(10)
    # add both encrypted numbers together
    encrypted_sum = ciphertext1 + ciphertext2
    # ...communication...
    # check that encrypted sum is not zero (in fact it is 100)
    assert not encrypted_sum.is_zero()
    # subtract the number 100
    encrypted_sum -= 100
    # check that encrypted sum is zero
    assert encrypted_sum.is_zero()
```

Running the examples above will show several warnings. The remainder of this
documentation explains why the warnings are issued and how to get rid of them
depending on the users' preferences.

## Fresh and unfresh ciphertexts

An encrypted message is called a ciphertext. A ciphertext in the current package
has a property `is_fresh` that indicates whether this ciphertext has fresh
randomness, in which case it can be communicated to another player securely.
More specifically, a ciphertext `c` is fresh if another user, knowledgeable of
all prior communication and all current ciphertexts marked as fresh, cannot
deduce any more private information from learning `c`.

The package understands that the freshness of the result of a homomorphic
operation depends on the freshness of the inputs, and that the homomorphic
operation renders the inputs unfresh. For example, if `c1` and `c2` are fresh
ciphertexts, then `c12 = c1 + c2` is marked as a fresh encryption (no
rerandomization needed) of the sum of the two underlying plaintexts. After the
operation, ciphertexts `c1` and `c2` are no longer fresh.

The fact that `c1` and `c2` were both fresh implies that, at some point, we
randomized them. After the operation `c12 = c1 + c2`, only `c12` is fresh. This
implies that one randomization was lost in the process. In particular, we wasted
resources. An alternative approach was to have unfresh `c1` and `c2` then
compute the unfresh result `c12` and only randomize that ciphertext. This time,
no resources were wasted. The package issues a warning to inform the user this
and similar efficiency opportunities.

The package integrates naturally with `tno.mpc.communication` and if that is
used for communication, its serialization logic will ensure that all sent
ciphertexts are fresh. A warning is issued if a ciphertext was randomized in the
proces. A ciphertext is always marked as unfresh after it is serialized.
Similarly, all received ciphertexts are considered unfresh.

## Tailor behavior to your needs

The crypto-neutral developer is facilitated by the package as follows: the
package takes care of all bookkeeping, and the serialization used by
`tno.mpc.communication` takes care of all randomization. The warnings can be
[disabled](#warnings) for a smoother experience.

The eager crypto-youngster can improve their understanding and hone their skills
by learning from the warnings that the package provides in a safe environment.
The package is safe to use when combined with `tno.mpc.communication`. It
remains to be safe while you transform your code from 'randomize-early' (fresh
encryptions) to 'randomize-late' (unfresh encryptions, randomize before
exposure). At that point you have optimized the efficiency of the library while
ensuring that all exposed ciphertexts are fresh before they are serialized. In
particular, you no longer rely on our serialization for (re)randomizing your
ciphertexts.

Finally, the experienced cryptographer can turn off warnings / turn them into
exceptions, or benefit from the `is_fresh` flag for own purposes (e.g. different
serializer or communication).

### Warnings

By default, the `warnings` package prints only the first occurrence of a warning
for each location (module + line number) where the warning is issued. The user
may easily
[change this behaviour](https://docs.python.org/3/library/warnings.html#the-warnings-filter)
to never see warnings:

```py
from tno.mpc.encryption_schemes.dgk import EncryptionSchemeWarning

warnings.simplefilter("ignore", EncryptionSchemeWarning)
```

Alternatively, the user may pass `"once"`, `"always"` or even `"error"`.

Finally, note that some operations issue two warnings, e.g. `c1-c2` issues a
warning for computing `-c2` and a warning for computing `c1 + (-c2)`.

## Advanced usage

The [basic usage](#basic-usage) can be improved upon by explicitly randomizing
at late as possible.

```python
from tno.mpc.encryption_schemes.dgk import DGK

if __name__ == "__main__":
    dgk_scheme = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1, full_decryption=False)
    # unsafe_encrypt does NOT randomize the generated ciphertext; it is deterministic still
    ciphertext1 = dgk_scheme.unsafe_encrypt(8.1)
    ciphertext1 += 0.9
    ciphertext1 *= 10
    ciphertext2 = dgk_scheme.unsafe_encrypt(10)
    # no randomness can be wasted by adding the two unfresh encryptions
    encrypted_sum = ciphertext1 + ciphertext2
    # randomize the result, which is now fresh
    encrypted_sum.randomize()
    # ...communication...
    decrypted_sum = dgk_scheme.decrypt(encrypted_sum)
    assert decrypted_sum == 100
```

As explained [above](#fresh-and-unfresh-ciphertexts), this implementation avoids
wasted randomization for `encrypted_sum` and therefore is more efficient.

## Speed-up encrypting and randomizing

Encrypting messages and randomizing ciphertexts is an involved operation that
requires randomly generating large values and processing them in some way. This
process can be sped up which will boost the performance of your script or
package. The base package `tno.mpc.encryption_schemes.templates` provides
several ways to more quickly generate randomness and we will show two of them
below.

### Generate randomness with multiple processes on the background

The simplest improvement gain is to generate the required amount of randomness
as soon as the scheme is initialized (so prior to any call to `randomize` or
`encrypt`):

```py
from tno.mpc.encryption_schemes.dgk import DGK

if __name__ == "__main__":
    dgk_scheme = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1)
    dgk_scheme.boot_randomness_generation(amount=5)
    # Possibly do some stuff here
    for msg in range(5):
        # The required randomness for encryption is already prepared, so this operation is faster.
        dgk_scheme.encrypt(msg)
    dgk_scheme.shut_down()
```

Calling `DGK.boot_randomness_generation` will generate a number of processes
that is each tasked with generating some of the requested randomness. By
default, the number of processes equals the number of CPUs on your device.

### Share DGK scheme and generate randomness a priori

A more advanced approach is to generate the randomness a priori and store it.
Then, if you run your main protocol, all randomness is readily available. This
looks as follows. First, the key-generating party generates a public-private
keypair and shares the public key with the other participants. Now, every player
pregenerates the amount of randomness needed for her part of the protocol and
stores it in a file. For example, this can be done overnight or during the
weekend. When the main protocol is executed, every player uses the same scheme
(public key) as communicated before, configures the scheme to use the
pregenerated randomness from file, and runs the main protocol without the need
to generate randomness for encryption at that time. A minimal example is
provided below.

```py
from pathlib import Path
from typing import List

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.templates.random_sources import FileSource

from tno.mpc.encryption_schemes.dgk import DGK, DGKCiphertext


def initialize_and_store_scheme() -> None:
    # Generate scheme
    scheme = DGK.from_security_parameter(v_bits=160, n_bits=1000, u=10009, precision=1)

    # Store without secret key for others
    with open(Path("scheme_without_secret_key"), "wb") as file:
        file.write(Serialization.pack(scheme, msg_id="", use_pickle=False))

    # Store with secret key for own use
    scheme.share_secret_key = True
    with open(Path("scheme_with_secret_key"), "wb") as file:
        file.write(Serialization.pack(scheme, msg_id="", use_pickle=False))

    # Tidy up to simulate real environment (program terminates)
    scheme.clear_instances()


def load_scheme(path: Path) -> DGK:
    # Load scheme from disk
    with open(path, "rb") as file:
        scheme_raw = file.read()
    return Serialization.unpack(scheme_raw)[1]


def pregenerate_randomness_in_weekend(scheme: DGK, amount: int, path: Path) -> None:
    # Generate randomness
    scheme.boot_randomness_generation(amount)
    # Save randomness to comma-separated csv
    with open(path, "w") as file:
        for _ in range(amount):
            file.write(f"{scheme.get_randomness()},")
    # Shut down processes gracefully
    scheme.shut_down()


def show_pregenerated_randomness(scheme: DGK, amount: int, path: Path) -> None:
    # Configure file as randomness source
    scheme.register_randomness_source(FileSource(path))
    # Consume randomness from file
    for i in range(amount):
        print(f"Random element {i}: {scheme.get_randomness()}")


def use_pregenerated_randomness_in_encryption(
    scheme: DGK, amount: int, path: Path
) -> List[DGKCiphertext]:
    # Configure file as randomness source
    scheme.register_randomness_source(FileSource(path))
    # Consume randomness from file
    ciphertexts = [scheme.encrypt(_) for _ in range(amount)]
    return ciphertexts


def decrypt_result(scheme: DGK, ciphertexts: List[DGKCiphertext]) -> None:
    # Show result
    for i, c in enumerate(ciphertexts):
    for i, ciphertext in enumerate(ciphertexts):
        print(f"Decryption of ciphertext {i}: {scheme.decrypt(ciphertext)}")


if __name__ == "__main__":
    AMOUNT = 5
    RANDOMNESS_PATH = Path("randomness.csv")

    # Alice initializes, stores and distributes the DGK scheme
    initialize_and_store_scheme()

    # Tidy up to simulate real environment (second party doesn't yet have the DGK instance)
    DGK.clear_instances()

    # Bob loads the DGK scheme, pregenerates randomness and encrypts the values 0,...,AMOUNT-1
    scheme_without_secret_key = load_scheme("scheme_without_secret_key")
    assert (
        scheme_without_secret_key.secret_key is None
    ), "Loaded dgk scheme contains secret key! This is not supposed to happen."
    pregenerate_randomness_in_weekend(
        scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH
    )
    show_pregenerated_randomness(scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH)
    # Prints the following to screen (numbers will be different):
    # Random element 0: 663667452419034735381232312860937013...
    # Random element 1: ...
    # ...
    ciphertexts = use_pregenerated_randomness_in_encryption(
        scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH
    )

    # Tidy up to simulate real environment (first party should use own DGK instance)
    DGK.clear_instances()

    # Alice receives the ciphertexts from Bob and decrypts them
    scheme_with_secret_key = load_scheme("scheme_with_secret_key")
    decrypt_result(scheme_with_secret_key, ciphertexts)
    # Prints the following to screen:
    # Decryption of ciphertext 0: 0.0
    # Decryption of ciphertext 1: 1.0
    # ...
```
