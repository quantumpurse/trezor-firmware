"""An extended BIP-39 mnemonic (36/54/72 words) is SPHINCS+ only.

No BIP-32 seed is derived from it, so every BTC/ETH/CKB-ECDSA/Cardano request
must fail, while the session still opens and SPHINCS+ keeps working. Standard
mnemonics must be unaffected.
"""

import pytest

from trezorlib import btc, cardano, ckb, ethereum, messages
from trezorlib.debuglink import TrezorTestContext
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from .test_sign_sphincs_tx import (
    MNEMONIC_BIP39_12,
    MNEMONIC_SPHINCS,
    MNEMONIC_SPHINCS_54,
    MNEMONIC_SPHINCS_72,
    _load_sphincs_session,
)

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.ckb,
    pytest.mark.models("t3w1"),
    pytest.mark.setup_client(uninitialized=True),
]

SPHINCS_ONLY = "SPHINCS\\+ only"

# One SHA2 "s" variant per security level the mnemonic length keys.
EXTENDED = [
    pytest.param(MNEMONIC_SPHINCS, 49, id="36w"),
    pytest.param(MNEMONIC_SPHINCS_54, 51, id="54w"),
    pytest.param(MNEMONIC_SPHINCS_72, 53, id="72w"),
]


@pytest.mark.parametrize("mnemonic, variant", EXTENDED)
def test_extended_mnemonic_rejects_bip32(
    test_ctx: TrezorTestContext, mnemonic: str, variant: int
):
    # Opening the session must not try to derive a seed.
    session = _load_sphincs_session(test_ctx, mnemonic)

    session.refresh_features()
    assert session.features.sphincs_only is True

    with pytest.raises(TrezorFailure, match=SPHINCS_ONLY):
        btc.get_public_node(session, parse_path("m/84h/0h/0h"), coin_name="Bitcoin")
    with pytest.raises(TrezorFailure, match=SPHINCS_ONLY):
        ethereum.get_address(session, parse_path("m/44h/60h/0h/0/0"))
    with pytest.raises(TrezorFailure, match=SPHINCS_ONLY):
        ckb.get_address(session, parse_path("m/44h/309h/0h/0/0"), network="Mainnet")

    # ...while SPHINCS+, which reads the mnemonic itself, still works.
    resp = ckb.get_sphincs_address(session, network="Mainnet", variant=variant)
    assert resp.address


def test_extended_mnemonic_rejects_cardano(test_ctx: TrezorTestContext):
    _load_sphincs_session(test_ctx)
    session = test_ctx.get_session(derive_cardano=True)

    for derivation_type in (
        messages.CardanoDerivationType.ICARUS,
        messages.CardanoDerivationType.ICARUS_TREZOR,
    ):
        with pytest.raises(TrezorFailure, match="not enabled"):
            cardano.get_public_key(
                session, parse_path("m/1852h/1815h/0h"), derivation_type
            )
    with pytest.raises(TrezorFailure, match=SPHINCS_ONLY):
        cardano.get_public_key(
            session,
            parse_path("m/1852h/1815h/0h"),
            messages.CardanoDerivationType.LEDGER,
        )


def test_standard_mnemonic_unaffected(test_ctx: TrezorTestContext):
    session = _load_sphincs_session(test_ctx, MNEMONIC_BIP39_12)

    session.refresh_features()
    assert not session.features.sphincs_only

    assert btc.get_public_node(
        session, parse_path("m/84h/0h/0h"), coin_name="Bitcoin"
    ).xpub
    with pytest.raises(TrezorFailure, match="extended mnemonic"):
        ckb.get_sphincs_address(session, network="Mainnet")
