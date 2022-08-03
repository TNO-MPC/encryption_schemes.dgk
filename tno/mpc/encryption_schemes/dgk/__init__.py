"""
Implementation of the Damgard, Geisler and Kroigard (DGK) cryptosystem.
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncryptionSchemeWarning as EncryptionSchemeWarning,
)

from tno.mpc.encryption_schemes.dgk.dgk import DGK as DGK
from tno.mpc.encryption_schemes.dgk.dgk import DGKCiphertext as DGKCiphertext
from tno.mpc.encryption_schemes.dgk.dgk import DGKPublicKey as DGKPublicKey
from tno.mpc.encryption_schemes.dgk.dgk import DGKSecretKey as DGKSecretKey

__version__ = "2.1.1"
