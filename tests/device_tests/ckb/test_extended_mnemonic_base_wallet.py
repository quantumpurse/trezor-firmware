"""An extended BIP-39 mnemonic (36/54/72 words) is three standard phrases.

The first one is the base wallet: every non-SPHINCS+ coin on the device must
derive exactly what a standard BIP-39 device derives from those words alone.
"""

import pytest

from trezorlib import btc, cardano, ckb, debuglink, device, messages
from trezorlib.client import PassphraseSetting
from trezorlib.debuglink import TrezorTestContext
from trezorlib.tools import parse_path

from .test_sign_sphincs_tx import (
    MNEMONIC_SPHINCS,
    MNEMONIC_SPHINCS_54,
    MNEMONIC_SPHINCS_72,
)

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.ckb,
    pytest.mark.cardano,
    pytest.mark.models("t3w1"),
    pytest.mark.setup_client(uninitialized=True),
]

CKB_PATH = parse_path("m/44h/309h/0h/0/0")
BTC_PATH = parse_path("m/84h/0h/0h/0/0")
ADA_PATH = parse_path("m/1852h/1815h/0h/0/0")


def _base_phrase(mnemonic: str) -> str:
    words = mnemonic.split(" ")
    return " ".join(words[: len(words) // 3])


def _wallet_fingerprint(test_ctx: TrezorTestContext, mnemonic: str, passphrase: str):
    debuglink.load_device(
        test_ctx.get_seedless_session(),
        mnemonic=mnemonic,
        pin="",
        passphrase_protection=bool(passphrase),
        label="test",
        skip_checksum=len(mnemonic.split(" ")) > 24,
    )
    session = test_ctx.get_session(
        passphrase=passphrase or PassphraseSetting.STANDARD_WALLET,
        derive_cardano=True,
    )
    fingerprint = (
        ckb.get_address(session, CKB_PATH, show_display=False, network="Mainnet"),
        btc.get_address(
            session,
            "Bitcoin",
            BTC_PATH,
            show_display=False,
            script_type=messages.InputScriptType.SPENDWITNESS,
        ),
        cardano.get_public_key(session, ADA_PATH).xpub,
        cardano.get_public_key(
            session, ADA_PATH, messages.CardanoDerivationType.ICARUS_TREZOR
        ).xpub,
    )
    device.wipe(test_ctx.get_seedless_session())
    return fingerprint


@pytest.mark.parametrize(
    "mnemonic",
    [MNEMONIC_SPHINCS, MNEMONIC_SPHINCS_54, MNEMONIC_SPHINCS_72],
    ids=["36w", "54w", "72w"],
)
@pytest.mark.parametrize("passphrase", ["", "hidden"], ids=["nopass", "pass"])
def test_extended_mnemonic_equals_base_wallet(
    test_ctx: TrezorTestContext, mnemonic: str, passphrase: str
):
    extended = _wallet_fingerprint(test_ctx, mnemonic, passphrase)
    base = _wallet_fingerprint(test_ctx, _base_phrase(mnemonic), passphrase)
    assert extended == base
