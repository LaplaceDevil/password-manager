import os
from typing import Optional, Callable

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a master key from a human-memorable password using Argon2id.

    This function is intentionally slow and memory-hard to make
    offline brute-force attacks expensive if the vault file is stolen.

    Parameters
    ----------
    password : str
        Master password provided by the user.
    salt : bytes, optional
        Random salt stored in the vault metadata.

    Returns
    -------
    bytes
        A 32-byte master key suitable for further key derivation.
    
    Examples
    --------
    >>> salt = bytes.fromhex('a1b2c3d4e5f67890a1b2c3d4e5f67890')
    >>> user_pass = "sea_of_tuna"
    >>> derive_master_key(user_pass, salt).hex()
    '0b89406ff8c40be2187ca2d602824e2bf3a488c98f6b911c6d0fd977794c5b7c'
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def derive_enc_key(master_key: bytes) -> bytes:
    """
    Derive an encryption key from the master key using HKDF.

    This step isolates the encryption key from the raw master key
    and allows future extension (e.g., separate MAC keys).

    Parameters
    ----------
    master_key : bytes
        Output of the Argon2id key derivation.

    Returns
    -------
    bytes
        A 32-byte AES-256 encryption key.
    
    Examples
    --------
    >>> salt = bytes.fromhex('a1b2c3d4e5f67890a1b2c3d4e5f67890')
    >>> user_pass = "sea_of_tuna"
    >>> argon_key = derive_master_key(user_pass, salt)
    >>> encryption_key = derive_enc_key(argon_key)
    >>> encryption_key.hex()
    '3ccd2083c93c9229f3956d408ae8ec3342c285486ee44c43adbb942643af2000'
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"passman encryption key",
    )
    return hkdf.derive(master_key)


def encrypt(enc_key: bytes, plaintext: bytes, random_function: Optional[Callable[[int], bytes]] = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    AES-GCM provides both confidentiality and integrity (AEAD).
    A fresh random nonce is generated for each encryption.

    Parameters
    ----------
    enc_key : bytes
        Symmetric encryption key.
    plaintext : bytes
        Data to encrypt.
    random_function : callable, optional
        Function to generate random bytes for the nonce. Defaults to os.urandom.

    Returns
    -------
    tuple[bytes, bytes]
        (nonce, ciphertext_with_tag)
    
    Examples
    --------
    >>> enc_key = bytes.fromhex('3ccd2083c93c9229f3956d408ae8ec3342c285486ee44c43adbb942643af2000')
    >>> user_password = b'my_absolutely_secret_password'
    >>> # Seed the random function for ensure reproducibility for this example
    >>> # In production, you should not seed the random function and use os.urandom directly.
    >>> nonce, ciphertext = encrypt(
    ...     enc_key,
    ...     user_password,
    ...     random_function=lambda n: bytes.fromhex('00112233445566778899aabb'))
    >>> ciphertext.hex()
    '81c552c1214bd251855c68e62317ad0af81ca2083894756d25fc7b47ecbf85eb46af2db5242c1405299c40d945'
    """
    if random_function is None:
        random_function = os.urandom
    nonce = random_function(12)
    aes = AESGCM(enc_key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(enc_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.

    If the ciphertext or nonce was modified, decryption will fail.

    Parameters
    ----------
    enc_key : bytes
        Symmetric encryption key.
    nonce : bytes
        Nonce used during encryption.
    ciphertext : bytes
        Encrypted data including authentication tag.

    Returns
    -------
    bytes
        Decrypted plaintext.
    
    Examples
    --------
    >>> enc_key = bytes.fromhex('3ccd2083c93c9229f3956d408ae8ec3342c285486ee44c43adbb942643af2000')
    >>> nonce = bytes.fromhex('00112233445566778899aabb')
    >>> ciphertext = bytes.fromhex('81c552c1214bd251855c68e62317ad0af81ca2083894756d25fc7b47ecbf85eb46af2db5242c1405299c40d945')
    >>> decrypt(enc_key, nonce, ciphertext)
    b'my_absolutely_secret_password'
    """
    aes = AESGCM(enc_key)
    return aes.decrypt(nonce, ciphertext, None)
