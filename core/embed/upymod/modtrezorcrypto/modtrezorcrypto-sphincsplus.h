/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/objstr.h"

#include "hkdf.h"
#include "memzero.h"
#include "sphincsplus_dispatch.h"

/*
 * SPHINCS+ key derivation and signing for the CKB post-quantum lock script.
 *
 * Supports all 12 SLH-DSA parameter sets via a runtime dispatch table.
 * Each variant is compiled with namespaced symbols (spx_{name}_*) and
 * selected at runtime by variant_id (48-59).
 *
 * Derivation flow (matching key-vault-wasm):
 *   1. Master seed (48/72/96 bytes) split into 3 equal parts
 *   2. Each part derived via HKDF-SHA256 with info path
 *   3. Concatenated → variant-specific keygen
 */

/* Variant ID constants */
#define SPX_VARIANT_SHA2_128F   48
#define SPX_VARIANT_SHA2_128S   49
#define SPX_VARIANT_SHA2_192F   50
#define SPX_VARIANT_SHA2_192S   51
#define SPX_VARIANT_SHA2_256F   52
#define SPX_VARIANT_SHA2_256S   53
#define SPX_VARIANT_SHAKE_128F  54
#define SPX_VARIANT_SHAKE_128S  55
#define SPX_VARIANT_SHAKE_192F  56
#define SPX_VARIANT_SHAKE_192S  57
#define SPX_VARIANT_SHAKE_256F  58
#define SPX_VARIANT_SHAKE_256S  59

/// package: trezorcrypto.sphincsplus

/// def derive_keypair(
///     master_seed: bytes, account_index: int, variant: int
/// ) -> tuple[bytes, bytes]:
///     """
///     Derive SPHINCS+ keypair from master seed and account index.
///     Returns (public_key, secret_key).
///     Supports all 12 variants (IDs 48-59).
///     """
STATIC mp_obj_t mod_trezorcrypto_sphincsplus_derive_keypair(mp_obj_t seed_obj,
                                                             mp_obj_t index_obj,
                                                             mp_obj_t variant_obj) {
  mp_buffer_info_t seed = {0};
  mp_get_buffer_raise(seed_obj, &seed, MP_BUFFER_READ);

  int account_index = mp_obj_get_int(index_obj);
  int variant = mp_obj_get_int(variant_obj);

  if (account_index < 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("Negative SPHINCS+ account index"));
  }

  const spx_variant_t *v = spx_get_variant(variant);
  if (v == NULL) {
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported SPHINCS+ variant"));
  }

  int n = (int)v->spx_n;
  size_t expected_seed_len = (size_t)(3 * n);
  if (seed.len != expected_seed_len) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid master seed length"));
  }

  /* Build the HKDF info string. This string is part of the key derivation
   * consensus — any change here invalidates every previously derived key,
   * so keep it byte-for-byte identical across firmware versions and host
   * implementations. */
  char info[64];
  int info_len = snprintf(info, sizeof(info),
                          "ckb/quantum-purse/sphincs-plus/%d", account_index);
  if (info_len < 0 || info_len >= (int)sizeof(info)) {
    mp_raise_ValueError(MP_ERROR_TEXT("Account index too large"));
  }

  /* Split + HKDF derive each component */
  const uint8_t *sk_seed_raw = (const uint8_t *)seed.buf;
  const uint8_t *sk_prf_raw = sk_seed_raw + n;
  const uint8_t *pk_seed_raw = sk_prf_raw + n;

  uint8_t derived_seed[96]; /* max 3*32=96 */
  hkdf_sha256(NULL, 0, sk_seed_raw, n,
              (const uint8_t *)info, info_len, derived_seed, n);
  hkdf_sha256(NULL, 0, sk_prf_raw, n,
              (const uint8_t *)info, info_len, derived_seed + n, n);
  hkdf_sha256(NULL, 0, pk_seed_raw, n,
              (const uint8_t *)info, info_len, derived_seed + 2 * n, n);

  /* Generate keypair via dispatch */
  vstr_t pk = {0};
  vstr_init_len(&pk, v->pk_bytes);
  vstr_t sk = {0};
  vstr_init_len(&sk, v->sk_bytes);

  int ret = v->seed_keypair((unsigned char *)pk.buf,
                            (unsigned char *)sk.buf, derived_seed);
  memzero(derived_seed, sizeof(derived_seed));

  if (ret != 0) {
    vstr_clear(&pk);
    vstr_clear(&sk);
    mp_raise_ValueError(MP_ERROR_TEXT("SPHINCS+ keygen failed"));
  }

  mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
  tuple->items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &pk);
  tuple->items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &sk);
  return MP_OBJ_FROM_PTR(tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezorcrypto_sphincsplus_derive_keypair_obj,
    mod_trezorcrypto_sphincsplus_derive_keypair);

/// def sign(secret_key: bytes, message: bytes, variant: int) -> bytes:
///     """
///     Sign a message with SPHINCS+ secret key.
///     Returns the detached signature.
///     """
STATIC mp_obj_t mod_trezorcrypto_sphincsplus_sign(size_t n_args,
                                                   const mp_obj_t *args) {
  mp_buffer_info_t sk = {0}, msg = {0};
  mp_get_buffer_raise(args[0], &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[1], &msg, MP_BUFFER_READ);
  int variant = mp_obj_get_int(args[2]);

  const spx_variant_t *v = spx_get_variant(variant);
  if (v == NULL) {
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported SPHINCS+ variant"));
  }
  if (sk.len != v->sk_bytes) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid secret key length"));
  }
  if (msg.len == 0) {
    mp_raise_ValueError(MP_ERROR_TEXT("Empty message"));
  }

  vstr_t sig = {0};
  vstr_init_len(&sig, v->sig_bytes);

  /* Copy the secret key into a local scratch buffer so we can zeroize it
   * after use. The caller's sk.buf lives inside a Python bytes object and
   * cannot be wiped from here, but at least we avoid leaving a secondary
   * copy in the dispatch path. */
  uint8_t sk_scratch[128]; /* max sk_bytes across all variants */
  if (sk.len > sizeof(sk_scratch)) {
    vstr_clear(&sig);
    mp_raise_ValueError(MP_ERROR_TEXT("Secret key too large"));
  }
  memcpy(sk_scratch, sk.buf, sk.len);

  size_t actual_sig_len = 0;
  int ret = v->sign((uint8_t *)sig.buf, &actual_sig_len,
                    (const uint8_t *)msg.buf, msg.len, sk_scratch);

  memzero(sk_scratch, sizeof(sk_scratch));

  if (ret != 0) {
    vstr_clear(&sig);
    mp_raise_ValueError(MP_ERROR_TEXT("SPHINCS+ signing failed"));
  }

  sig.len = actual_sig_len;
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_sphincsplus_sign_obj, 3, 3,
    mod_trezorcrypto_sphincsplus_sign);

/// def verify(
///     public_key: bytes, signature: bytes, message: bytes, variant: int
/// ) -> bool:
///     """
///     Verify a SPHINCS+ signature.
///     """
STATIC mp_obj_t mod_trezorcrypto_sphincsplus_verify(size_t n_args,
                                                     const mp_obj_t *args) {
  mp_buffer_info_t pk = {0}, sig = {0}, msg = {0};
  mp_get_buffer_raise(args[0], &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(args[1], &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(args[2], &msg, MP_BUFFER_READ);
  int variant = mp_obj_get_int(args[3]);

  const spx_variant_t *v = spx_get_variant(variant);
  if (v == NULL) {
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported SPHINCS+ variant"));
  }
  if (pk.len != v->pk_bytes) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid public key length"));
  }

  int ret = v->verify((const uint8_t *)sig.buf, sig.len,
                      (const uint8_t *)msg.buf, msg.len,
                      (const uint8_t *)pk.buf);

  return mp_obj_new_bool(ret == 0);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezorcrypto_sphincsplus_verify_obj, 4, 4,
    mod_trezorcrypto_sphincsplus_verify);

/// def publickey(secret_key: bytes, variant: int) -> bytes:
///     """
///     Extract public key from secret key.
///     """
STATIC mp_obj_t mod_trezorcrypto_sphincsplus_publickey(mp_obj_t sk_obj,
                                                       mp_obj_t variant_obj) {
  mp_buffer_info_t sk = {0};
  mp_get_buffer_raise(sk_obj, &sk, MP_BUFFER_READ);
  int variant = mp_obj_get_int(variant_obj);

  const spx_variant_t *v = spx_get_variant(variant);
  if (v == NULL) {
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported SPHINCS+ variant"));
  }
  if (sk.len != v->sk_bytes) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid secret key length"));
  }

  vstr_t pk = {0};
  vstr_init_len(&pk, v->pk_bytes);

  /* PK = SK[2*N..4*N] = [PUB_SEED || root] */
  size_t n = v->spx_n;
  memcpy(pk.buf, (const uint8_t *)sk.buf + 2 * n, v->pk_bytes);

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pk);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_sphincsplus_publickey_obj,
                                 mod_trezorcrypto_sphincsplus_publickey);

/// def get_variant_info(variant: int) -> tuple[int, int, int, int]:
///     """
///     Returns (spx_n, pk_bytes, sk_bytes, sig_bytes) for a variant.
///     """
STATIC mp_obj_t mod_trezorcrypto_sphincsplus_get_variant_info(
    mp_obj_t variant_obj) {
  int variant = mp_obj_get_int(variant_obj);
  const spx_variant_t *v = spx_get_variant(variant);
  if (v == NULL) {
    mp_raise_ValueError(MP_ERROR_TEXT("Unsupported SPHINCS+ variant"));
  }
  mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(4, NULL));
  tuple->items[0] = mp_obj_new_int(v->spx_n);
  tuple->items[1] = mp_obj_new_int(v->pk_bytes);
  tuple->items[2] = mp_obj_new_int(v->sk_bytes);
  tuple->items[3] = mp_obj_new_int(v->sig_bytes);
  return MP_OBJ_FROM_PTR(tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezorcrypto_sphincsplus_get_variant_info_obj,
    mod_trezorcrypto_sphincsplus_get_variant_info);

STATIC const mp_rom_map_elem_t
    mod_trezorcrypto_sphincsplus_globals_table[] = {
        {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_sphincsplus)},
        {MP_ROM_QSTR(MP_QSTR_derive_keypair),
         MP_ROM_PTR(&mod_trezorcrypto_sphincsplus_derive_keypair_obj)},
        {MP_ROM_QSTR(MP_QSTR_sign),
         MP_ROM_PTR(&mod_trezorcrypto_sphincsplus_sign_obj)},
        {MP_ROM_QSTR(MP_QSTR_verify),
         MP_ROM_PTR(&mod_trezorcrypto_sphincsplus_verify_obj)},
        {MP_ROM_QSTR(MP_QSTR_publickey),
         MP_ROM_PTR(&mod_trezorcrypto_sphincsplus_publickey_obj)},
        {MP_ROM_QSTR(MP_QSTR_get_variant_info),
         MP_ROM_PTR(&mod_trezorcrypto_sphincsplus_get_variant_info_obj)},
        /* Variant constants */
        {MP_ROM_QSTR(MP_QSTR_SHA2_128F), MP_ROM_INT(SPX_VARIANT_SHA2_128F)},
        {MP_ROM_QSTR(MP_QSTR_SHA2_128S), MP_ROM_INT(SPX_VARIANT_SHA2_128S)},
        {MP_ROM_QSTR(MP_QSTR_SHA2_192F), MP_ROM_INT(SPX_VARIANT_SHA2_192F)},
        {MP_ROM_QSTR(MP_QSTR_SHA2_192S), MP_ROM_INT(SPX_VARIANT_SHA2_192S)},
        {MP_ROM_QSTR(MP_QSTR_SHA2_256F), MP_ROM_INT(SPX_VARIANT_SHA2_256F)},
        {MP_ROM_QSTR(MP_QSTR_SHA2_256S), MP_ROM_INT(SPX_VARIANT_SHA2_256S)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_128F), MP_ROM_INT(SPX_VARIANT_SHAKE_128F)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_128S), MP_ROM_INT(SPX_VARIANT_SHAKE_128S)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_192F), MP_ROM_INT(SPX_VARIANT_SHAKE_192F)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_192S), MP_ROM_INT(SPX_VARIANT_SHAKE_192S)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_256F), MP_ROM_INT(SPX_VARIANT_SHAKE_256F)},
        {MP_ROM_QSTR(MP_QSTR_SHAKE_256S), MP_ROM_INT(SPX_VARIANT_SHAKE_256S)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_sphincsplus_globals,
                            mod_trezorcrypto_sphincsplus_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_sphincsplus_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_sphincsplus_globals,
};
