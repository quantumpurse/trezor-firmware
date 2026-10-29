from typing import TYPE_CHECKING

import storage.device as storage_device
from trezor import utils

from . import backup_types

if TYPE_CHECKING:
    from trezor.enums import BackupType
    from trezor.ui import ProgressLayout


SPHINCS_ONLY_ERROR = "Extended mnemonics support SPHINCS+ only."


def get() -> tuple[bytes | None, BackupType]:
    return get_secret(), get_type()


def get_secret() -> bytes | None:
    return storage_device.get_mnemonic_secret()


def get_type() -> BackupType:
    return storage_device.get_backup_type()


def is_bip39() -> bool:
    """
    If False then SLIP-39 (either Basic or Advanced).
    Other invalid values are checked directly in storage.
    """
    from trezor.enums import BackupType

    return get_type() == BackupType.Bip39


def is_sphincs_only() -> bool:
    """
    True if the stored mnemonic is an extended (36/54/72-word) BIP-39 one, which
    only SPHINCS+ consumes. No BIP-32 seed is derived from it.
    """
    secret = get_secret()
    return (
        secret is not None and is_bip39() and storage_device.is_extended_bip39(secret)
    )


def get_seed(
    passphrase: str = "",
    progress_bar: bool = True,
    mnemonic_secret: bytes | None = None,
) -> bytes:
    mnemonic_secret = mnemonic_secret or get_secret()
    if mnemonic_secret is None:
        raise ValueError  # Mnemonic not set
    if is_bip39() and storage_device.is_extended_bip39(mnemonic_secret):
        from trezor.wire import DataError

        raise DataError(SPHINCS_ONLY_ERROR)

    render_func = None
    if progress_bar and not utils.DISABLE_ANIMATION:
        _start_progress()
        render_func = _render_progress

    if is_bip39():
        from trezor.crypto import bip39

        seed = bip39.seed(mnemonic_secret.decode(), passphrase, render_func)

    else:  # SLIP-39
        from trezor.crypto import slip39

        identifier = storage_device.get_slip39_identifier()
        extendable = backup_types.is_extendable_backup_type(get_type())
        iteration_exponent = storage_device.get_slip39_iteration_exponent()
        if iteration_exponent is None:
            # Exponent expected but not found
            raise RuntimeError
        seed = slip39.decrypt(
            mnemonic_secret,
            passphrase.encode(),
            iteration_exponent,
            identifier,
            extendable,
            render_func,
        )

    return seed


if not utils.BITCOIN_ONLY:

    def derive_cardano_icarus(
        passphrase: str = "",
        trezor_derivation: bool = True,
        progress_bar: bool = True,
    ) -> bytes:
        if not is_bip39():
            raise ValueError  # should not be called for SLIP-39

        binary_mnemonic = storage_device.get_binary_mnemonic()
        if binary_mnemonic is None:
            raise RuntimeError("Failed to get binary mnemonic.")

        render_func = None
        if progress_bar and not utils.DISABLE_ANIMATION:
            _start_progress()
            render_func = _render_progress

        from trezor.crypto import cardano

        seed = cardano.derive_icarus(
            binary_mnemonic,
            passphrase,
            trezor_derivation,
            render_func,
        )
        _finish_progress()
        return seed


_progress_obj: ProgressLayout | None = None


def _start_progress() -> None:
    from trezor import workflow
    from trezor.ui.layouts.progress import progress

    global _progress_obj

    # Because we are drawing to the screen manually, without a layout, we
    # should make sure that no other layout is running.
    workflow.close_others()
    _progress_obj = progress()


def _render_progress(progress: int, total: int) -> None:
    if _progress_obj is not None:
        _progress_obj.report(1000 * progress // total)


def _finish_progress() -> None:
    global _progress_obj
    _progress_obj = None
