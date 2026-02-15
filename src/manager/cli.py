import argparse
import getpass
import sys

from vault import Vault, VAULT_PATH


def cmd_init(_args):
    """
    Initialize a new password vault.
    """
    print(f"Creating new vault at {VAULT_PATH}")

    pw1 = getpass.getpass("Set master password: ")
    pw2 = getpass.getpass("Confirm master password: ")

    if pw1 != pw2:
        print("Error: passwords do not match", file=sys.stderr)
        sys.exit(1)

    Vault.create(pw1)
    print("Vault initialized successfully.")


def _unlock_vault() -> Vault:
    """
    Load and unlock an existing vault.
    """
    try:
        vault = Vault.load()
    except FileNotFoundError:
        print("Vault not found. Run `passman init` first.", file=sys.stderr)
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")
    vault.unlock(master_password)
    return vault


def cmd_add(args):
    """
    Add a new password entry.
    """
    vault = _unlock_vault()

    password = getpass.getpass(f"Password for {args.service}: ")
    vault.add(args.service, args.username, password)

    print(f"Entry added for {args.service}")


def cmd_get(args):
    """
    Retrieve a password from the vault.
    """
    vault = _unlock_vault()

    try:
        password = vault.get(args.service)
    except KeyError:
        print("Service not found.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Decryption failed. Wrong password or corrupted vault.", file=sys.stderr)
        sys.exit(1)

    print(password)


def cmd_list(_args):
    """
    List all stored services.
    """
    vault = _unlock_vault()

    if not vault.data["entries"]:
        print("Vault is empty.")
        return

    for entry in vault.data["entries"]:
        print(f"{entry['service']} ({entry['username']})")

def cmd_change_master(_args):
    """
    Change the master password for the vault.
    """
    vault = _unlock_vault()

    old_pw = getpass.getpass("Current master password: ")
    new_pw1 = getpass.getpass("New master password: ")
    new_pw2 = getpass.getpass("Confirm new master password: ")

    if new_pw1 != new_pw2:
        print("Error: passwords do not match", file=sys.stderr)
        sys.exit(1)

    try:
        vault.change_master(old_pw, new_pw1)
    except Exception as e:
        print(f"Failed to change master password: {e}", file=sys.stderr)
        sys.exit(1)

    print("Master password changed successfully!")


def build_parser() -> argparse.ArgumentParser:
    """
    Build the top-level argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="passman",
        description="Minimal local password manager",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize a new vault")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Add a new password")
    p_add.add_argument("service", help="Service name (e.g. github.com)")
    p_add.add_argument(
        "-u",
        "--username",
        default="",
        help="Username associated with the service",
    )
    p_add.set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="Retrieve a password")
    p_get.add_argument("service", help="Service name")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List stored services")
    p_list.set_defaults(func=cmd_list)

    p_chmp = sub.add_parser("change-master", help="Change the master password")
    p_chmp.set_defaults(func=cmd_change_master)

    return parser


def main(argv=None):
    """
    CLI entrypoint.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
