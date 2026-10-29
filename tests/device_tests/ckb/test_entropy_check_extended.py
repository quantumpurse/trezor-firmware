"""Entropy check on extended BIP-39 mnemonics (36/54/72 words).

An extended mnemonic is SPHINCS+ only and has no BIP-32 wallet, so the device
proves the secret with a digest of the whole mnemonic instead of XPUBs. 256
bits is the upstream control: that path must keep working unchanged.
"""

import hashlib

import pytest

from trezorlib import device, messages
from trezorlib.debuglink import TrezorTestContext

from ...common import MOCK_GET_ENTROPY

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.ckb,
    pytest.mark.models("t3w1"),
    pytest.mark.setup_client(uninitialized=True),
]


def _reset_msg(strength: int) -> messages.ResetDevice:
    return messages.ResetDevice(
        strength=strength,
        backup_type=messages.BackupType.Bip39,
        skip_backup=True,
        pin_protection=False,
        passphrase_protection=False,
        entropy_check=True,
    )


@pytest.mark.parametrize("strength", [256, 384, 576, 768])
def test_entropy_check_extended(test_ctx: TrezorTestContext, strength: int):
    path_xpubs = device.setup(
        test_ctx.get_seedless_session(),
        strength=strength,
        entropy_check_count=2,
        backup_type=messages.BackupType.Bip39,
        skip_backup=True,
        pin_protection=False,
        passphrase_protection=False,
        _get_entropy=MOCK_GET_ENTROPY,
    )

    words = test_ctx.debug.state().mnemonic_secret.decode().split(" ")
    assert len(words) == strength // 32 * 3
    # XPUBs exist only for a standard mnemonic.
    assert bool(path_xpubs) == (strength <= 256)


@pytest.mark.parametrize("strength", [256, 384])
def test_entropy_check_ready_digest(test_ctx: TrezorTestContext, strength: int):
    """full_phrase_digest is set exactly for extended mnemonics, and it is the
    SHA-256 of the mnemonic the device ends up storing."""
    session = test_ctx.get_seedless_session()
    session.call(_reset_msg(strength), expect=messages.EntropyRequest)
    ready = session.call(
        messages.EntropyAck(entropy=MOCK_GET_ENTROPY()),
        expect=messages.EntropyCheckReady,
    )
    session.call(messages.EntropyCheckContinue(finish=True), expect=messages.Success)

    if strength <= 256:
        assert ready.full_phrase_digest is None
    else:
        secret = test_ctx.debug.state().mnemonic_secret
        assert ready.full_phrase_digest == hashlib.sha256(secret).digest()
