"""Entropy check on extended BIP-39 mnemonics (36/54/72 words).

The device answers the check with XPUBs of the base wallet (first sub-phrase),
and the host must derive the same from the entropy it verified. 256 bits is
the upstream control: that path must keep working unchanged.
"""

import pytest
from mnemonic import Mnemonic
from slip10 import SLIP10

from trezorlib import device, messages
from trezorlib.btc import get_public_node
from trezorlib.debuglink import TrezorTestContext

from ...common import MOCK_GET_ENTROPY

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.ckb,
    pytest.mark.models("t3w1"),
    pytest.mark.setup_client(uninitialized=True),
]


@pytest.mark.parametrize("strength", [256, 384, 576, 768])
def test_entropy_check_extended(test_ctx: TrezorTestContext, strength: int):
    session = test_ctx.get_seedless_session()
    path_xpubs = device.setup(
        session,
        strength=strength,
        entropy_check_count=2,
        backup_type=messages.BackupType.Bip39,
        skip_backup=True,
        pin_protection=False,
        passphrase_protection=False,
        _get_entropy=MOCK_GET_ENTROPY,
    )
    assert path_xpubs

    mnemonic = test_ctx.debug.state().mnemonic_secret.decode()
    words = mnemonic.split(" ")
    assert len(words) == strength // 32 * 3
    base_phrase = " ".join(words[: len(words) // 3]) if len(words) > 24 else mnemonic
    slip10 = SLIP10.from_seed(Mnemonic.to_seed(base_phrase, passphrase=""))

    session = test_ctx.get_session()
    for path, xpub in path_xpubs:
        # the XPUBs proven during the check are the wallet's real XPUBs...
        assert get_public_node(session, path).xpub == xpub
        # ...and they are derived from the base phrase alone
        assert slip10.get_xpub_from_path(path) == xpub
