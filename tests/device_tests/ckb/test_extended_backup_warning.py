"""The extended backup must warn that sub-phrase 1 is also the SPHINCS+ key.

HKDF turns the first sub-phrase into SK_SEED, and SK_SEED plus the on-chain
PUB_SEED is enough to forge signatures - so restoring those words alone into
other software hands over the post-quantum key. Standard backups must not grow
the extra screen.
"""

import pytest

from trezorlib import device, messages
from trezorlib.debuglink import TrezorTestContext

from ...common import MOCK_GET_ENTROPY
from ...input_flows import InputFlowBase, get_mnemonic

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.ckb,
    pytest.mark.models("t3w1"),
    pytest.mark.setup_client(uninitialized=True),
]

WARNING_BR = "backup_extended_base_phrase"
# Last screen before the words, in both the standard and the extended flow.
LAST_BR_BEFORE_WORDS = "backup_warning"


class _ResetBackupFlow(InputFlowBase):
    """Like InputFlowBip39ResetBackup, but records ButtonRequest names.

    Screens are consumed by name rather than by count, so a missing screen ends
    the loop and fails an assertion instead of desyncing the flow into a hang.
    """

    def __init__(self, ctx):
        super().__init__(ctx)
        self.mnemonic = None
        self.br_names: list[str] = []

    def input_flow_eckhart(self):
        for _ in range(8):  # generous cap; the real flow is 5 or 6 screens
            br = yield
            self.br_names.append(br.name)
            self.debug.press_yes()
            if br.name == LAST_BR_BEFORE_WORDS:
                break

        self.mnemonic = yield from get_mnemonic(self.debug)


def _reset(test_ctx: TrezorTestContext, strength: int) -> _ResetBackupFlow:
    flow = _ResetBackupFlow(test_ctx)
    with test_ctx:
        test_ctx.set_input_flow(flow.get())
        device.setup(
            test_ctx.get_seedless_session(),
            strength=strength,
            entropy_check_count=0,
            backup_type=messages.BackupType.Bip39,
            pin_protection=False,
            passphrase_protection=False,
            _get_entropy=MOCK_GET_ENTROPY,
        )

    assert flow.br_names[-1] == LAST_BR_BEFORE_WORDS
    return flow


@pytest.mark.parametrize("strength, words", [(384, 36), (768, 72)])
def test_extended_backup_warns(test_ctx: TrezorTestContext, strength: int, words: int):
    flow = _reset(test_ctx, strength)

    assert flow.mnemonic is not None
    assert len(flow.mnemonic.split()) == words
    assert WARNING_BR in flow.br_names
    # Directly before the generic "never make a digital copy" warning.
    assert flow.br_names[-2] == WARNING_BR


def test_standard_backup_has_no_extra_screen(test_ctx: TrezorTestContext):
    # 24 words is the upstream control: the flow must be untouched.
    flow = _reset(test_ctx, 256)

    assert flow.mnemonic is not None
    assert len(flow.mnemonic.split()) == 24
    assert WARNING_BR not in flow.br_names
