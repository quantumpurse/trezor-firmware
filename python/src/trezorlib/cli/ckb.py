"""CKB (Nervos Network) CLI commands."""

import click
from typing import TYPE_CHECKING

from .. import ckb, tools
from . import with_session

if TYPE_CHECKING:
    from ..transport.session import Session


PATH_HELP = "BIP-32 path, e.g. m/44'/309'/0'/0/0"


@click.group(name="ckb")
def cli() -> None:
    """CKB (Nervos Network) commands."""


@cli.command()
@click.option(
    "-n", "--address", default=ckb.DEFAULT_BIP32_PATH, help=PATH_HELP
)
@click.option("-d", "--show-display", is_flag=True)
@click.option(
    "--coin",
    type=click.Choice(["Mainnet", "Testnet"]),
    required=True,
    help="Network: Mainnet or Testnet",
)
@click.option("-C", "--chunkify", is_flag=True)
@with_session
def get_address(
    session: "Session",
    address: str,
    show_display: bool,
    coin: str,
    chunkify: bool,
) -> str:
    """Get CKB address for specified path."""
    address_n = tools.parse_path(address)
    return ckb.get_address(
        session,
        address_n,
        show_display=show_display,
        network=coin,
        chunkify=chunkify,
    )


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option(
    "--coin",
    type=click.Choice(["Mainnet", "Testnet"]),
    default="Mainnet",
    help="Network (default: Mainnet)",
)
@click.option("-C", "--chunkify", is_flag=True)
@click.argument("json_file", type=click.File("r"))
@with_session
def sign_tx(
    session: "Session",
    address: str,
    coin: str,
    chunkify: bool,
    json_file,
) -> str:
    """Sign CKB transaction from JSON file."""
    import json

    address_n = tools.parse_path(address)
    tx_data = json.load(json_file)

    inputs = []
    for inp in tx_data.get("inputs", []):
        inputs.append(ckb.create_cell_input(
            tx_hash=inp["tx_hash"],
            index=inp["index"],
            since=inp.get("since", 0),
        ))

    outputs = []
    for out in tx_data.get("outputs", []):
        outputs.append(ckb.create_cell_output(
            capacity=out["capacity"],
            lock_code_hash=out["lock_code_hash"],
            lock_hash_type=out["lock_hash_type"],
            lock_args=out["lock_args"],
            type_code_hash=out.get("type_code_hash"),
            type_hash_type=out.get("type_hash_type"),
            type_args=out.get("type_args"),
            data=bytes.fromhex(out["data"].removeprefix("0x")) if out.get("data") else None,
        ))

    cell_deps = []
    for dep in tx_data.get("cell_deps", []):
        cell_deps.append(ckb.create_cell_dep(
            tx_hash=dep["tx_hash"],
            index=dep["index"],
            dep_type=dep["dep_type"],
        ))

    fee = tx_data.get("fee")

    result = ckb.sign_tx(
        session,
        address_n,
        inputs=inputs,
        outputs=outputs,
        cell_deps=cell_deps,
        network=coin,
        fee=fee,
        chunkify=chunkify,
    )

    return (
        f"Signature: 0x{result.serialized.signature.hex()}\n"
        f"TX Hash: 0x{result.serialized.tx_hash.hex()}"
    )


@cli.command(name="get-sphincs-address")
@click.option(
    "-i",
    "--account",
    type=int,
    default=0,
    show_default=True,
    help="SPHINCS+ account index (fed into the HKDF info string)",
)
@click.option(
    "-v",
    "--variant",
    type=click.Choice(list(ckb.SPHINCS_VARIANTS.keys())),
    default="sha2-128s",
    show_default=True,
    help="SPHINCS+ parameter set",
)
@click.option(
    "--coin",
    type=click.Choice(["Mainnet", "Testnet"]),
    required=True,
    help="Network: Mainnet or Testnet",
)
@click.option("-d", "--show-display", is_flag=True)
@click.option("-C", "--chunkify", is_flag=True)
@with_session
def get_sphincs_address(
    session: "Session",
    account: int,
    variant: str,
    coin: str,
    show_display: bool,
    chunkify: bool,
) -> str:
    """Get a CKB SPHINCS+ post-quantum address.

    Derives the SPHINCS+ keypair on-device from the wallet mnemonic via
    HKDF-SHA256 and returns the corresponding CKB Bech32m address.
    """
    variant_id = ckb.SPHINCS_VARIANTS[variant]
    result = ckb.sphincs_get_address(
        session,
        network=coin,
        account_index=account,
        variant=variant_id,
        show_display=show_display,
        chunkify=chunkify,
    )
    return (
        f"Address: {result.address}\n"
        f"Variant: {variant} ({variant_id})\n"
        f"Lock args: 0x{result.lock_args.hex()}\n"
        f"Public key: 0x{result.public_key.hex()}"
    )


@cli.command(name="sign-sphincs-tx")
@click.option(
    "-i",
    "--account",
    type=int,
    default=0,
    show_default=True,
    help="SPHINCS+ account index (fed into the HKDF info string)",
)
@click.option(
    "-v",
    "--variant",
    type=click.Choice(list(ckb.SPHINCS_VARIANTS.keys())),
    default="sha2-128s",
    show_default=True,
    help="SPHINCS+ parameter set",
)
@click.option(
    "--coin",
    type=click.Choice(["Mainnet", "Testnet"]),
    default="Mainnet",
    help="Network (default: Mainnet)",
)
@click.option("-C", "--chunkify", is_flag=True)
@click.argument("json_file", type=click.File("r"))
@with_session
def sign_sphincs_tx(
    session: "Session",
    account: int,
    variant: str,
    coin: str,
    chunkify: bool,
    json_file,
) -> str:
    """Sign CKB transaction with SPHINCS+ from JSON file."""
    import json

    variant_id = ckb.SPHINCS_VARIANTS[variant]
    tx_data = json.load(json_file)

    inputs = []
    for inp in tx_data.get("inputs", []):
        inputs.append(ckb.create_cell_input(
            tx_hash=inp["tx_hash"],
            index=inp["index"],
            since=inp.get("since", 0),
        ))

    outputs = []
    for out in tx_data.get("outputs", []):
        outputs.append(ckb.create_cell_output(
            capacity=out["capacity"],
            lock_code_hash=out["lock_code_hash"],
            lock_hash_type=out["lock_hash_type"],
            lock_args=out["lock_args"],
            type_code_hash=out.get("type_code_hash"),
            type_hash_type=out.get("type_hash_type"),
            type_args=out.get("type_args"),
            data=bytes.fromhex(out["data"].removeprefix("0x")) if out.get("data") else None,
        ))

    cell_deps = []
    for dep in tx_data.get("cell_deps", []):
        cell_deps.append(ckb.create_cell_dep(
            tx_hash=dep["tx_hash"],
            index=dep["index"],
            dep_type=dep["dep_type"],
        ))

    fee = tx_data.get("fee")

    result = ckb.sphincs_sign_tx(
        session,
        inputs=inputs,
        outputs=outputs,
        cell_deps=cell_deps,
        network=coin,
        account_index=account,
        variant=variant_id,
        fee=fee,
        chunkify=chunkify,
    )

    return (
        f"Signature: 0x{result.serialized.signature.hex()}\n"
        f"Signature size: {len(result.serialized.signature)} bytes\n"
        f"TX Hash: 0x{result.serialized.tx_hash.hex()}"
    )
