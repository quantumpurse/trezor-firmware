"""CKB SPHINCS+ transaction signing handler.

Reuses the CKB streaming protocol (CKBTxRequest/CKBTxAckInput/Output/CellDep)
but signs with SPHINCS+ instead of secp256k1 ECDSA.

Key difference from ECDSA:
- uses ckb_tx_message_all hash (personal="ckb-sphincs+-msg") instead of
  standard sighash_all (personal="ckb-default-hash")
- on-chain verifier is FIPS 205 SLH-DSA; the vendored Round-3 SPHINCS+ library
  is wrapped by prepending the FIPS 205 domain separator to the digest.
"""

from typing import TYPE_CHECKING

from trezor.crypto.hashlib import blake2b
from trezor.wire import DataError

from . import helpers

if TYPE_CHECKING:
    from trezor.messages import (
        CKBSphincsPlusSignTx,
        CKBTxRequest,
        CKBCellInput,
        CKBCellOutput,
        CKBCellDep,
    )

# Import serialization helpers from ECDSA sign_tx (same CKB format)
from .sign_tx import (
    _serialize_uint64_le,
    _compute_raw_tx_hash,
    _serialize_bytes,
    _serialize_uint32_le,
)

# SPHINCS+ lock script constants
from .get_sphincs_address import (
    _CODE_HASH_MAINNET,
    _CODE_HASH_TESTNET,
    _HASH_TYPE_MAINNET,
    _HASH_TYPE_TESTNET,
    _VALID_VARIANTS,
    _split_extended_mnemonic_to_seed,
    _compute_lock_args,
)

# Upper bounds to prevent DoS via huge streaming loops. CKB transactions in
# practice never approach these, so rejecting above is safe.
_MAX_INPUTS = 256
_MAX_OUTPUTS = 256
_MAX_CELL_DEPS = 64
# Upper bound for account_index to prevent HKDF info-string overflow and keep
# the derivation path enumerable.
_MAX_ACCOUNT_INDEX = 1_000_000

# SPHINCS+ variant ID ranges per SLH-DSA security level. Index into this list
# matches the seed-length bucket below.
_VARIANT_IDS_BY_N = {
    16: (48, 49, 54, 55),   # sha2/shake 128f/s -> n=16
    24: (50, 51, 56, 57),   # sha2/shake 192f/s -> n=24
    32: (52, 53, 58, 59),   # sha2/shake 256f/s -> n=32
}


def _variant_spx_n(variant: int) -> int:
    for n, ids in _VARIANT_IDS_BY_N.items():
        if variant in ids:
            return n
    raise DataError("Unsupported SPHINCS+ variant")


def _create_sphincs_witness_placeholder(lock_size: int) -> bytes:
    """Create WitnessArgs with variable-size zero placeholder in lock field.

    Same Molecule encoding as ECDSA but with larger placeholder.
    """
    lock_bytes = bytes(lock_size)
    lock_serialized = _serialize_bytes(lock_bytes)

    header_size = 4 + (3 * 4)  # 16 bytes
    offset_lock = header_size
    offset_input_type = offset_lock + len(lock_serialized)
    offset_output_type = offset_input_type  # empty
    total_size = offset_output_type

    result = bytearray()
    result.extend(_serialize_uint32_le(total_size))
    result.extend(_serialize_uint32_le(offset_lock))
    result.extend(_serialize_uint32_le(offset_input_type))
    result.extend(_serialize_uint32_le(offset_output_type))
    result.extend(lock_serialized)

    return bytes(result)


def _serialize_cell_output_molecule(
    capacity: int,
    lock_code_hash: bytes,
    lock_hash_type: int,
    lock_args: bytes,
) -> bytes:
    """Serialize a CellOutput (with empty type_) in CKB Molecule format.

    Only the lock script is encoded; type_ is None because the current
    SPHINCS+ flow only supports plain CKB transfers. Cell data is also
    assumed empty for the same reason — the sighash computer writes
    `u32 LE 0` after this blob and never appends a payload.
    """
    args_serialized = _serialize_bytes(lock_args)
    script_header_size = 4 + (3 * 4)
    script_offset_code_hash = script_header_size
    script_offset_hash_type = script_offset_code_hash + 32
    script_offset_args = script_offset_hash_type + 1
    script_total_size = script_offset_args + len(args_serialized)

    script = bytearray()
    script.extend(_serialize_uint32_le(script_total_size))
    script.extend(_serialize_uint32_le(script_offset_code_hash))
    script.extend(_serialize_uint32_le(script_offset_hash_type))
    script.extend(_serialize_uint32_le(script_offset_args))
    script.extend(lock_code_hash)
    script.extend(bytes([lock_hash_type]))
    script.extend(args_serialized)

    cell_header_size = 4 + (3 * 4)
    cell_offset_capacity = cell_header_size
    cell_offset_lock = cell_offset_capacity + 8
    cell_offset_type = cell_offset_lock + len(script)
    cell_total_size = cell_offset_type  # type_ = None -> 0 bytes

    cell = bytearray()
    cell.extend(_serialize_uint32_le(cell_total_size))
    cell.extend(_serialize_uint32_le(cell_offset_capacity))
    cell.extend(_serialize_uint32_le(cell_offset_lock))
    cell.extend(_serialize_uint32_le(cell_offset_type))
    cell.extend(_serialize_uint64_le(capacity))
    cell.extend(script)

    return bytes(cell)


def _compute_sphincs_sighash(
    tx_hash: bytes,
    input_cells: list[tuple[int, bytes, int, bytes]],
    inputs_count: int,
) -> bytes:
    """Compute ckb_tx_message_all hash for SPHINCS+ signing.

    Matches ckb-fips205-utils::generate_ckb_tx_message_all for the common
    case covered by this handler:
    - every input belongs to the SPHINCS+ script group (plain transfers),
    - every input cell carries empty data and no type script,
    - the first WitnessArgs has no input_type and no output_type,
    - there are no witnesses beyond the inputs range.
    Extending beyond this (sUDT, DAO, cross-chain) means extending the
    proto with cell_data / cell_type / extra witnesses again.
    """
    h = blake2b(outlen=32, personal=b"ckb-sphincs+-msg")

    # 1. tx_hash of the raw transaction (without witnesses).
    h.update(tx_hash)

    # 2. For each input cell: molecule(cell_output) || u32 LE 0 (empty data).
    for capacity, lock_code_hash, lock_hash_type, lock_args in input_cells:
        cell_output_mol = _serialize_cell_output_molecule(
            capacity, lock_code_hash, lock_hash_type, lock_args
        )
        h.update(cell_output_mol)
        h.update(_serialize_uint32_le(0))

    # 3. First witness of the script group: only the (empty) input_type and
    #    output_type fields as length-prefixed Option<Bytes>. The lock
    #    placeholder itself is NOT part of the digest by construction.
    h.update(_serialize_uint32_le(0))
    h.update(_serialize_uint32_le(0))

    # 4. Remaining witnesses of the same script group — all empty
    #    WitnessArgs — encoded as u32 LE 0.
    for _ in range(inputs_count - 1):
        h.update(_serialize_uint32_le(0))

    return h.digest()


def _construct_witness_lock_prefix(variant: int, public_key: bytes) -> bytes:
    """Build the 5+pk_len byte prefix for witness lock.

    Format: [0x80, 0x00, 0x01, 0x01, flag] || pubkey
    where flag = (variant << 1) | 1  (has_signature bit set)
    """
    flag = ((variant << 1) | 1) & 0xFF
    return bytes([0x80, 0x00, 0x01, 0x01, flag]) + public_key


def _is_change_output(
    output: "CKBCellOutput",
    sender_lock_args: bytes,
    sender_code_hash: bytes,
    sender_hash_type: int,
) -> bool:
    """An output is change iff it targets the sender's lock and has no type."""
    return (
        output.lock_args == sender_lock_args
        and output.lock_code_hash == sender_code_hash
        and output.lock_hash_type == sender_hash_type
        and output.type_code_hash is None
    )


async def sign_sphincs_tx(msg: "CKBSphincsPlusSignTx") -> "CKBTxRequest":
    from trezor import TR
    from trezor.crypto import sphincsplus
    from trezor.enums import CKBTxRequestType
    from trezor.messages import (
        CKBTxRequest,
        CKBTxRequestDetails,
        CKBTxRequestSerialized,
        CKBTxAckInput,
        CKBTxAckOutput,
        CKBTxAckCellDep,
    )
    # CKBTxAckExtraWitness is a newer message type. Firmware builds that
    # predate it must still be able to sign the common-case transaction
    # (no extra witnesses), so we defer the import to the streaming loop
    # and only resolve it when the host actually asks us to read extras.
    from trezor.ui.layouts import confirm_output, confirm_total
    from trezor.wire.context import call

    from apps.common.mnemonic import get_secret

    # Validate inputs
    variant = msg.variant if msg.variant is not None else 49
    if variant not in _VALID_VARIANTS:
        raise DataError("Invalid SPHINCS+ variant")

    network = msg.network or "Mainnet"
    if network not in ("Mainnet", "Testnet"):
        raise DataError("Invalid CKB network")

    account_index = msg.account_index if msg.account_index is not None else 0
    if account_index < 0 or account_index > _MAX_ACCOUNT_INDEX:
        raise DataError("Invalid SPHINCS+ account index")

    if msg.inputs_count == 0 or msg.inputs_count > _MAX_INPUTS:
        raise DataError("Invalid inputs_count")
    if msg.outputs_count == 0 or msg.outputs_count > _MAX_OUTPUTS:
        raise DataError("Invalid outputs_count")
    cell_deps_count = msg.cell_deps_count or 0
    if cell_deps_count > _MAX_CELL_DEPS:
        raise DataError("Invalid cell_deps_count")

    # Get variant info for signature size
    spx_n, pk_bytes_len, sk_bytes_len, sig_bytes_len = (
        sphincsplus.get_variant_info(variant)
    )

    # Derive keypair from mnemonic
    mnemonic_secret = get_secret()
    if mnemonic_secret is None:
        raise DataError("Device not initialized")

    seed = _split_extended_mnemonic_to_seed(mnemonic_secret)
    # The seed length is fixed by the stored mnemonic and must match the
    # requested variant's security level. Mismatches mean the user picked a
    # variant that does not correspond to the backup they generated.
    expected_seed_len = 3 * _variant_spx_n(variant)
    if len(seed) != expected_seed_len:
        raise DataError(
            "SPHINCS+ variant does not match the stored mnemonic strength"
        )

    public_key, secret_key = sphincsplus.derive_keypair(seed, account_index, variant)

    # Compute sender lock args for change detection
    sender_lock_args = _compute_lock_args(public_key, variant)
    if network == "Mainnet":
        sender_code_hash = _CODE_HASH_MAINNET
        sender_hash_type = _HASH_TYPE_MAINNET
    else:
        sender_code_hash = _CODE_HASH_TESTNET
        sender_hash_type = _HASH_TYPE_TESTNET

    # Collect inputs via streaming. Every input must carry the cell metadata
    # used by ckb_tx_message_all. Plain transfers pass the same lock script
    # on every input — the handler enforces this so the single-group witness
    # schedule below stays correct.
    inputs: list[CKBCellInput] = []
    input_cells: list[tuple[int, bytes, int, bytes]] = []
    for i in range(msg.inputs_count):
        req = CKBTxRequest(
            request_type=CKBTxRequestType.TXINPUT,
            details=CKBTxRequestDetails(request_index=i),
        )
        ack = await call(req, CKBTxAckInput)
        if ack.input is None:
            raise DataError("Missing input data")
        inp = ack.input
        inputs.append(inp)

        if (
            inp.cell_capacity is None
            or inp.cell_lock_code_hash is None
            or inp.cell_lock_hash_type is None
            or inp.cell_lock_args is None
        ):
            raise DataError(
                "SPHINCS+ signing requires input cell metadata "
                "(cell_capacity, cell_lock_code_hash, cell_lock_hash_type, cell_lock_args)"
            )
        if len(inp.cell_lock_code_hash) != 32:
            raise DataError("cell_lock_code_hash must be 32 bytes")
        if inp.cell_lock_hash_type not in (0, 1, 2, 4):
            raise DataError("Invalid cell_lock_hash_type")
        if (
            inp.cell_lock_code_hash != sender_code_hash
            or inp.cell_lock_hash_type != sender_hash_type
            or inp.cell_lock_args != sender_lock_args
        ):
            # Every input must belong to the SPHINCS+ script group. Mixed
            # groups are not supported yet (would need multi-group sighash
            # semantics and are not required for plain transfers).
            raise DataError(
                "All inputs must share the signer's SPHINCS+ lock script"
            )

        input_cells.append((
            inp.cell_capacity,
            inp.cell_lock_code_hash,
            inp.cell_lock_hash_type,
            inp.cell_lock_args,
        ))

    # Collect outputs via streaming + user confirmation
    outputs: list[CKBCellOutput] = []
    outputs_data: list[bytes] = []
    send_amount = 0
    has_external_output = False

    for i in range(msg.outputs_count):
        req = CKBTxRequest(
            request_type=CKBTxRequestType.TXOUTPUT,
            details=CKBTxRequestDetails(request_index=i),
        )
        ack = await call(req, CKBTxAckOutput)
        if ack.output is None:
            raise DataError("Missing output data")
        output = ack.output
        outputs.append(output)
        outputs_data.append(output.data or b"")

        if not _is_change_output(
            output, sender_lock_args, sender_code_hash, sender_hash_type
        ):
            has_external_output = True

    # Show confirmation for non-change outputs
    self_send_shown = False
    for output in outputs:
        is_change = _is_change_output(
            output, sender_lock_args, sender_code_hash, sender_hash_type
        )

        if not is_change:
            show = True
        elif not has_external_output and not self_send_shown:
            # Pure self-send: still confirm the first output to give the user
            # a chance to abort.
            show = True
            self_send_shown = True
        else:
            show = False

        if show:
            send_amount += output.capacity
            address = helpers.encode_address_full(
                output.lock_code_hash,
                output.lock_hash_type,
                output.lock_args,
                network,
            )
            amount_str = helpers.format_amount(output.capacity)
            await confirm_output(
                address,
                amount_str,
                title=TR.send__confirm_sending,
                chunkify=bool(msg.chunkify),
            )

    # Collect cell_deps
    cell_deps: list[CKBCellDep] = []
    for i in range(cell_deps_count):
        req = CKBTxRequest(
            request_type=CKBTxRequestType.TXCELLDEP,
            details=CKBTxRequestDetails(request_index=i),
        )
        ack = await call(req, CKBTxAckCellDep)
        if ack.cell_dep is None:
            raise DataError("Missing cell_dep data")
        cell_deps.append(ack.cell_dep)

    # Compute transaction hash (same format as ECDSA — molecule hash of raw tx).
    tx_hash = _compute_raw_tx_hash(
        inputs=inputs,
        outputs=outputs,
        outputs_data=outputs_data,
        cell_deps=cell_deps,
    )

    # Use ckb_tx_message_all hash instead of standard sighash_all.
    sighash = _compute_sphincs_sighash(
        tx_hash=tx_hash,
        input_cells=input_cells,
        inputs_count=msg.inputs_count,
    )

    # Confirm total
    fee = msg.fee or 0
    await confirm_total(
        total_amount=helpers.format_amount(send_amount + fee),
        fee_amount=helpers.format_amount(fee),
        title=TR.words__title_summary,
    )

    # Sign with SPHINCS+.
    #
    # The vendored reference implementation is Round-3 SPHINCS+, but the CKB
    # on-chain lock script verifies FIPS 205 SLH-DSA signatures. FIPS 205
    # pure signing prepends the domain separator:
    #   M' = 0x00 || len(ctx) || ctx || M
    # With empty context this is two zero bytes. All other primitives match
    # (thash_simple, identical H_msg, PRF_msg, ADRS layout), so prefixing the
    # message is sufficient to turn Round-3 sign into FIPS 205 sign for all
    # sha2-* and shake-* variants used here.
    fips205_message = b"\x00\x00" + sighash
    try:
        raw_signature = sphincsplus.sign(secret_key, fips205_message, variant)
    finally:
        # Best-effort wipe of the secret key material. Python bytes are
        # immutable so we cannot zero the original buffer; C-side wiping is
        # done inside sphincsplus.sign after use. We drop our reference here
        # and let the allocator reuse the slot as soon as possible.
        secret_key = None  # noqa: F841
        del seed

    # Build witness lock prefix and stream the full witness lock content
    # (prefix + raw_signature) back to the host. SPHINCS+ signatures are up
    # to ~50 KB and exceed the THP per-message buffer, so we split them into
    # CHUNK_SIZE-byte pieces, each delivered as its own CKBTxRequest with
    # request_type=TXSIGCHUNK. The terminating TXFINISHED then carries only
    # the tx_hash (no signature payload).
    witness_lock_prefix = _construct_witness_lock_prefix(variant, public_key)
    full_signature = witness_lock_prefix + raw_signature

    # Lazy import — old firmware builds without the new proto fall through
    # this import error early enough to be reported, while new builds resolve
    # cleanly. The chunk size stays well below the THP buffer (~8 KB).
    from trezor.messages import CKBTxAckSigChunk

    CHUNK_SIZE = 4096
    total = len(full_signature)
    offset = 0
    while offset < total:
        end = offset + CHUNK_SIZE
        if end > total:
            end = total
        chunk_req = CKBTxRequest(
            request_type=CKBTxRequestType.TXSIGCHUNK,
            details=CKBTxRequestDetails(
                signature_offset=offset,
                signature_total_size=total,
            ),
            serialized=CKBTxRequestSerialized(
                signature=full_signature[offset:end],
            ),
        )
        await call(chunk_req, CKBTxAckSigChunk)
        offset = end

    return CKBTxRequest(
        request_type=CKBTxRequestType.TXFINISHED,
        serialized=CKBTxRequestSerialized(
            tx_hash=tx_hash,
        ),
    )
