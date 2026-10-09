from trezorutils import halt

if not __debug__:
    halt("Debugging is disabled")

if __debug__:
    layout_watcher = False

    # Sized for the largest reset entropy (768-bit extended mnemonic = 96 bytes).
    # Slice-assigning a longer value than the initial capacity would reallocate
    # this module-level buffer and permanently shrink the free heap, tripping the
    # __debug__ `Free heap size decreased` guard in trezor.utils.unimport.
    reset_internal_entropy = bytearray(96)
    reset_internal_entropy[:] = bytes()
