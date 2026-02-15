import json
import os
import base64
from crypto import derive_master_key, derive_enc_key, encrypt, decrypt


VAULT_PATH = os.path.expanduser("~/.passman.json")


def _b64e(b: bytes) -> str:
    """Encode bytes to base64 string for JSON storage."""
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    """Decode base64 string back to raw bytes."""
    return base64.b64decode(s)


class Vault:
    def __init__(self, data: dict):
        self.data = data
        self.enc_key = None
    
    def change_master(self, old_master_password: str, new_master_password: str):
        """
        Change the master password of the vault.

        This operation decrypts all entries using the old master password,
        generates a new salt, derives a new master key and encryption key,
        re-encrypts all entries with the new key, and updates the vault.

        Parameters
        ----------
        old_master_password : str
            Current master password to unlock the vault.
        new_master_password : str
            New master password to secure the vault.
        """
        # Step 1: Derive old key and unlock vault
        old_salt = _b64d(self.data["kdf"]["salt"])
        old_master_key = derive_master_key(old_master_password, old_salt)
        old_enc_key = derive_enc_key(old_master_key)

        # Step 2: Decrypt all passwords
        plaintext_entries = []
        for entry in self.data["entries"]:
            plaintext = decrypt(
                old_enc_key,
                _b64d(entry["nonce"]),
                _b64d(entry["ciphertext"]),
            )
            plaintext_entries.append((entry["service"], entry["username"], plaintext))

        # Step 3: Generate new salt and derive new keys
        new_salt = os.urandom(16)
        new_master_key = derive_master_key(new_master_password, new_salt)
        new_enc_key = derive_enc_key(new_master_key)

        # Step 4: Re-encrypt all entries
        new_entries = []
        for service, username, plaintext in plaintext_entries:
            nonce, ciphertext = encrypt(new_enc_key, plaintext)
            new_entries.append({
                "service": service,
                "username": username,
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ciphertext),
            })

        # Step 5: Update vault metadata and entries
        self.data["kdf"]["salt"] = _b64e(new_salt)
        self.data["entries"] = new_entries

        # Step 6: Save vault
        self.save()


    @classmethod
    def create(cls, master_password: str):
        """
        Create a new empty vault and initialize cryptographic parameters.

        This generates a fresh random salt and derives the encryption key
        from the provided master password.

        Parameters
        ----------
        master_password : str
            Master password chosen by the user.

        Returns
        -------
        Vault
            Initialized and unlocked vault instance.
        """
        salt = os.urandom(16)
        data = {
            "version": 1,
            "kdf": {
                "algorithm": "argon2id",
                "salt": _b64e(salt),
                "params": {"m": 65536, "t": 3, "p": 2},
            },
            "entries": [],
        }
        vault = cls(data)
        vault.unlock(master_password)
        vault.save()
        return vault

    @classmethod
    def load(cls):
        with open(VAULT_PATH, "r") as f:
            return cls(json.load(f))

    def unlock(self, master_password: str):
        """
        Unlock the vault using the master password.

        This derives the encryption key and keeps it in memory
        for the lifetime of the Vault instance.

        Parameters
        ----------
        master_password : str
            Master password provided by the user.
        """
        salt = _b64d(self.data["kdf"]["salt"])
        master_key = derive_master_key(master_password, salt)
        self.enc_key = derive_enc_key(master_key)

    def save(self):
        with open(VAULT_PATH, "w") as f:
            json.dump(self.data, f, indent=2)

    def add(self, service: str, username: str, password: str):
        """
        Add a new password entry to the vault.

        The password is encrypted before being stored.
        Metadata (service, username) remains in plaintext
        for usability reasons.

        Parameters
        ----------
        service : str
            Service identifier (e.g., "github.com").
        username : str
            Account username.
        password : str
            Plaintext password to encrypt and store.
        """
        nonce, ciphertext = encrypt(self.enc_key, password.encode())
        self.data["entries"].append(
            {
                "service": service,
                "username": username,
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ciphertext),
            }
        )
        self.save()
    
    def update(self, service: str, new_password: str):
        """
        Update (replace) the password for an existing service.

        The password is re-encrypted with a fresh nonce.
        Metadata (service, username) remains unchanged.

        Parameters
        ----------
        service : str
            Service identifier.
        new_password : str
            New plaintext password.

        Raises
        ------
        KeyError
            If the service is not found in the vault.
        """
        for entry in self.data["entries"]:
            if entry["service"] == service:
                nonce, ciphertext = encrypt(
                    self.enc_key,
                    new_password.encode(),
                )
                entry["nonce"] = _b64e(nonce)
                entry["ciphertext"] = _b64e(ciphertext)
                self.save()
                return

        raise KeyError("Service not found")

    def get(self, service: str) -> str:
        """
        Retrieve and decrypt a password for a given service.

        Parameters
        ----------
        service : str
            Service identifier.

        Returns
        -------
        str
            Decrypted plaintext password.

        Raises
        ------
        KeyError
            If the service is not found in the vault.
        """
        for e in self.data["entries"]:
            if e["service"] == service:
                return decrypt(
                    self.enc_key,
                    _b64d(e["nonce"]),
                    _b64d(e["ciphertext"]),
                ).decode()
        raise KeyError("Service not found")
