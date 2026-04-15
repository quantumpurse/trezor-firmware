"""Get CKB SPHINCS+ post-quantum address."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import CKBSphincsPlusAddress, CKBSphincsPlusGetAddress


# Fixed header bytes for the CKB all-in-one quantum-resistant lock script.
# Laid out as: [reserved, required_first_n, threshold, pubkey_num, sign_flag].
_MULTISIG_RESERVED_FIELD_VALUE = 0x80
_REQUIRED_FIRST_N = 0x00
_THRESHOLD = 0x01
_PUBKEY_NUM = 0x01

# Deployed code hashes of the CKB SPHINCS+ on-chain lock script.
_CODE_HASH_MAINNET = (
    b"\x30\x2d\x35\x98\x2f\x86\x5e\xbc"
    b"\xbe\xdb\x9a\x93\x60\xe4\x05\x30"
    b"\xed\x32\xad\xb8\xe1\x0b\x42\xfb"
    b"\xbe\x70\xd8\x31\x2f\xf7\xce\xdf"
)
_CODE_HASH_TESTNET = (
    b"\x14\x7e\xcb\xb5\xc5\x12\x7d\x98"
    b"\x2e\xe1\x36\x2d\x2c\x2b\xb4\x26"
    b"\x78\x03\xda\x2e\xb0\x06\xd1\x50"
    b"\xe8\x8a\xf6\xca\xaa\x0a\x7e\xaf"
)

# Hash type byte for the CKB full address payload.
# Mainnet uses "type" = 0x01, testnet uses "data1" = 0x02.
_HASH_TYPE_MAINNET = 0x01
_HASH_TYPE_TESTNET = 0x02

# Valid SPHINCS+ variant IDs (matching ParamId in ckb-fips205-utils).
_VALID_VARIANTS = (48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59)


def _split_extended_mnemonic_to_seed(mnemonic_bytes: bytes) -> bytes:
    """Convert an extended BIP-39 mnemonic into concatenated raw entropy.

    SPHINCS+ keygen needs 3*n bytes of raw entropy (n = 16/24/32 per security
    level). Only 36/54/72-word extended mnemonics carry enough entropy to
    produce that; standard BIP-39 mnemonics (12/18/24 words) do not and are
    rejected early with a clear message.
    """
    from trezor.crypto import bip39
    from trezor.wire import DataError

    text = mnemonic_bytes.decode()
    words = text.split(" ")
    word_count = len(words)

    if word_count not in (36, 54, 72):
        raise DataError(
            "SPHINCS+ requires an extended mnemonic (36, 54 or 72 words)"
        )

    sub_len = word_count // 3
    entropy_per_sub = (sub_len // 3) * 4
    parts = []
    for i in range(3):
        sub_phrase = " ".join(words[i * sub_len : (i + 1) * sub_len])
        sub_bits = bip39.mnemonic_to_bits(sub_phrase)
        parts.append(bytes(sub_bits)[:entropy_per_sub])
    return b"".join(parts)


def _compute_lock_args(public_key: bytes, variant: int) -> bytes:
    """Compute the 32-byte CKB lock_args from a SPHINCS+ public key.

    Format (matching key-vault-wasm/src/lib.rs::get_lock_scrip_arg):
        lock_args = blake2b_256(
            personal = "ckb-sphincs+-sct",
            data = [0x80, 0x00, 0x01, 0x01, sign_flag] || public_key
        )
    where sign_flag = (variant << 1) (no signature bit set in script args).
    """
    from trezor.crypto.hashlib import blake2b

    sign_flag = (variant << 1) & 0xFF

    h = blake2b(outlen=32, personal=b"ckb-sphincs+-sct")
    h.update(
        bytes(
            [
                _MULTISIG_RESERVED_FIELD_VALUE,
                _REQUIRED_FIRST_N,
                _THRESHOLD,
                _PUBKEY_NUM,
                sign_flag,
            ]
        )
    )
    h.update(public_key)
    return h.digest()


async def get_sphincs_address(
    msg: "CKBSphincsPlusGetAddress",
) -> "CKBSphincsPlusAddress":
    from trezor import TR
    from trezor.crypto import sphincsplus
    from trezor.messages import CKBSphincsPlusAddress
    from trezor.ui.layouts import show_address
    from trezor.wire import DataError

    from apps.common.mnemonic import get_secret

    from .helpers import encode_address_full

    # Validate inputs
    variant = msg.variant if msg.variant is not None else 49
    if variant not in _VALID_VARIANTS:
        raise DataError("Invalid SPHINCS+ variant")
    if not msg.network or msg.network not in ("Mainnet", "Testnet"):
        raise DataError("Invalid CKB network")

    account_index = msg.account_index if msg.account_index is not None else 0
    # Upper bound mirrors sign_sphincs_tx.py._MAX_ACCOUNT_INDEX and keeps the
    # HKDF info string well within the 64-byte buffer on the C side.
    if account_index < 0 or account_index > 1_000_000:
        raise DataError("Invalid SPHINCS+ account index")

    # Read mnemonic from device storage
    mnemonic_secret = get_secret()
    if mnemonic_secret is None:
        raise DataError("Device not initialized")

    # Build the master seed from the stored extended mnemonic. Seed length
    # is fixed by the mnemonic word count (36 -> 48, 54 -> 72, 72 -> 96
    # bytes) and must match the requested variant's security level
    # (n = 16/24/32).
    seed = _split_extended_mnemonic_to_seed(mnemonic_secret)
    # Variants are grouped by `n`: ids 48/49/54/55 -> n=16, 50/51/56/57 -> n=24,
    # 52/53/58/59 -> n=32.
    _n_by_variant = {
        48: 16, 49: 16, 54: 16, 55: 16,
        50: 24, 51: 24, 56: 24, 57: 24,
        52: 32, 53: 32, 58: 32, 59: 32,
    }
    expected_seed_len = 3 * _n_by_variant[variant]
    if len(seed) != expected_seed_len:
        raise DataError(
            "SPHINCS+ variant does not match the stored mnemonic strength"
        )

    # Derive SPHINCS+ keypair. Secret key material is wiped as soon as the
    # lock args are computed — this handler only needs the public key.
    public_key, _secret_key = sphincsplus.derive_keypair(
        seed, account_index, variant
    )
    try:
        # Build CKB lock script args
        lock_args = _compute_lock_args(public_key, variant)
    finally:
        # Best-effort drop of references so the allocator can reuse the slots.
        # Python bytes are immutable; we cannot zero in place.
        _secret_key = None  # noqa: F841
        del seed

    # Build CKB full address
    if msg.network == "Mainnet":
        code_hash = _CODE_HASH_MAINNET
        hash_type = _HASH_TYPE_MAINNET
    else:
        code_hash = _CODE_HASH_TESTNET
        hash_type = _HASH_TYPE_TESTNET

    address = encode_address_full(code_hash, hash_type, lock_args, msg.network)

    # Optionally show on display
    if msg.show_display:
        coin = "CKB SPHINCS+"
        await show_address(
            address,
            subtitle=TR.address__coin_address_template.format(coin),
            path="QP/{}/v{}".format(account_index, variant),
            chunkify=bool(msg.chunkify),
        )

    return CKBSphincsPlusAddress(
        address=address,
        lock_args=lock_args,
        public_key=public_key,
        variant=variant,
    )
