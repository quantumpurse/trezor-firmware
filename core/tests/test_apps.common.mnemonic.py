# flake8: noqa: F403,F405
from common import *  # isort:skip

import storage.device
from mock_storage import mock_storage
from trezor.crypto import bip39

from apps.common import mnemonic

# Three distinct standard phrases, each with a valid checksum.
BASE_12 = "all " * 11 + "all"
EXT_36 = " ".join(
    [
        BASE_12,
        " ".join(["abandon"] * 11 + ["about"]),
        " ".join(["zoo"] * 11 + ["abstract"]),
    ]
)
BASE_18 = " ".join(["abandon"] * 17 + ["agent"])
EXT_54 = " ".join(
    [BASE_18, " ".join(["all"] * 17 + ["action"]), " ".join(["zoo"] * 17 + ["advice"])]
)
BASE_24 = " ".join(["abandon"] * 23 + ["art"])
EXT_72 = " ".join(
    [BASE_24, " ".join(["all"] * 23 + ["answer"]), " ".join(["zoo"] * 23 + ["buddy"])]
)


class TestMnemonic(unittest.TestCase):
    def test_base_phrase_standard_unchanged(self):
        for phrase in (BASE_12, BASE_18, BASE_24, b"a b c"):
            if isinstance(phrase, str):
                phrase = phrase.encode()
            self.assertEqual(mnemonic.bip39_base_phrase(phrase), phrase)

    def test_base_phrase_extended(self):
        self.assertEqual(mnemonic.bip39_base_phrase(EXT_36.encode()), BASE_12.encode())
        self.assertEqual(mnemonic.bip39_base_phrase(EXT_54.encode()), BASE_18.encode())
        self.assertEqual(mnemonic.bip39_base_phrase(EXT_72.encode()), BASE_24.encode())

    @mock_storage
    def test_seed_extended_equals_base_wallet(self):
        for ext, base in ((EXT_36, BASE_12), (EXT_54, BASE_18), (EXT_72, BASE_24)):
            storage.device.store_mnemonic_secret(ext.encode())
            for passphrase in ("", "hidden"):
                self.assertEqual(
                    mnemonic.get_seed(passphrase, progress_bar=False),
                    bip39.seed(base, passphrase),
                )

    @mock_storage
    def test_seed_standard_unchanged(self):
        storage.device.store_mnemonic_secret(BASE_24.encode())
        self.assertEqual(
            mnemonic.get_seed("", progress_bar=False), bip39.seed(BASE_24, "")
        )

    @unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
    @mock_storage
    def test_binary_mnemonic_from_base_phrase(self):
        from trezor.crypto import cardano

        storage.device.store_mnemonic_secret(EXT_72.encode())
        self.assertEqual(
            storage.device.get_binary_mnemonic(), bip39.mnemonic_to_bits(BASE_24)
        )
        self.assertEqual(
            mnemonic.derive_cardano_icarus("", True, progress_bar=False),
            cardano.derive_icarus(bip39.mnemonic_to_bits(BASE_24), "", True),
        )


if __name__ == "__main__":
    unittest.main()
