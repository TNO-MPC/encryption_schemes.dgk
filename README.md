# TNO MPC Lab - Encryption Schemes - DGK

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package tno.mpc.encryption_schemes.dgk is part of the TNO Python Toolbox.

Implementation of the DGK encryption scheme with support for precomputation of randomness. The 
encryption scheme supports positive and negative numbers, as well as fixed point encoding of 
numbers. Homomorphic addition of ciphertexts, negation of ciphertexts, and multiplication of 
ciphertexts with integral scalars has been included as well.

*Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws.*  
*This implementation of cryptographic software has not been audited. Use at your own risk.*

## Documentation

Documentation of the tno.mpc.encryption_schemes.dgk package can be found [here](https://docs.mpc.tno.nl/encryption_schemes/dgk/2.1.1).

## Install

Easily install the tno.mpc.encryption_schemes.dgk package using pip:
```console
$ python -m pip install tno.mpc.encryption_schemes.dgk
```

### Note:
A significant performance improvement can be achieved by installing the GMPY2 library.
```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[gmpy]'
```

If you wish to use the tno.mpc.communication module you can use:
```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[communication]'
```

If you wish to run the tests you can use:
```console
$ python -m pip install 'tno.mpc.encryption_schemes.dgk[tests]'
```

## Usage

The DGK scheme can be used with and without support for full decryptions. When full decryptions are not supported one
can only use the private key to determine whether a ciphertext is zero or not.

Full decryption support requires the scheme to pre-compute and store a lookup table for all possible plaintexts. This
table can become impractically large when the plaintext space is big.

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

Running the examples above will show several warnings. The remainder of this documentation explains why the warnings are issued and how to get rid of them depending on the users' preferences.

## Fresh and unfresh ciphertexts

An encrypted message is called a ciphertext. A ciphertext in the current package has a property `is_fresh` that indicates whether this ciphertext has fresh randomness, in which case it can be communicated to another player securely. More specifically, a ciphertext `c` is fresh if another user, knowledgeable of all prior communication and all current ciphertexts marked as fresh, cannot deduce any more private information from learning `c`.

The package understands that the freshness of the result of a homomorphic operation depends on the freshness of the inputs, and that the homomorphic operation renders the inputs unfresh. For example, if `c1` and `c2` are fresh ciphertexts, then `c12 = c1 + c2` is marked as a fresh encryption (no rerandomization needed) of the sum of the two underlying plaintexts. After the operation, ciphertexts `c1` and `c2` are no longer fresh.

The fact that `c1` and `c2` were both fresh implies that, at some point, we randomized them. After the operation `c12 = c1 + c2`, only `c12` is fresh. This implies that one randomization was lost in the process. In particular, we wasted resources. An alternative approach was to have unfresh `c1` and `c2` then compute the unfresh result `c12` and only randomize that ciphertext. This time, no resources were wasted. The package issues a warning to inform the user this and similar efficiency opportunities.

The package integrates naturally with `tno.mpc.communication` and if that is used for communication, its serialization logic will ensure that all sent ciphertexts are fresh. A warning is issued if a ciphertext was randomized in the proces. A ciphertext is always marked as unfresh after it is serialized. Similarly, all received ciphertexts are considered unfresh.

## Tailor behavior to your needs

The crypto-neutral developer is facilitated by the package as follows: the package takes care of all bookkeeping, and the serialization used by `tno.mpc.communication` takes care of all randomization. The warnings can be [disabled](#warnings) for a smoother experience.

The eager crypto-youngster can improve their understanding and hone their skills by learning from the warnings that the package provides in a safe environment. The package is safe to use when combined with `tno.mpc.communication`. It remains to be safe while you transform your code from 'randomize-early' (fresh encryptions) to 'randomize-late' (unfresh encryptions, randomize before exposure). At that point you have optimized the efficiency of the library while ensuring that all exposed ciphertexts are fresh before they are serialized. In particular, you no longer rely on our serialization for (re)randomizing your ciphertexts.

Finally, the experienced cryptographer can turn off warnings / turn them into exceptions, or benefit from the `is_fresh` flag for own purposes (e.g. different serializer or communication).

### Warnings

By default, the `warnings` package prints only the first occurrence of a warning for each location (module + line number) where the warning is issued. The user may easily [change this behaviour](https://docs.python.org/3/library/warnings.html#the-warnings-filter) to never see warnings:

```py
from tno.mpc.encryption_schemes.dgk import EncryptionSchemeWarning

warnings.simplefilter("ignore", EncryptionSchemeWarning)
```

Alternatively, the user may pass `"once"`, `"always"` or even `"error"`.

Finally, note that some operations issue two warnings, e.g. `c1-c2` issues a warning for computing `-c2` and a warning for computing `c1 + (-c2)`.

## Advanced usage

The [basic usage](#basic-usage) can be improved upon by explicitly randomizing at late as possible.

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

As explained [above](#fresh-and-unfresh-ciphertexts), this implementation avoids wasted randomization for `encrypted_sum` and therefore is more efficient.
