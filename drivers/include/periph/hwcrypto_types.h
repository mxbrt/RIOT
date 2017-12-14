/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef HWCRYPTO_TYPES_H
#define HWCRYPTO_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_MAX_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define CIPHER_CTX_MAX_SIZE AES_MAX_KEY_SIZE + AES_BLOCK_SIZE * 2

typedef enum {
    HWCRYPTO_KEY_LENGTH_ERR = -1,
    HWCYRPTO_IV_ERR = -2,
    HWCRYPTO_IO_ERR = -3,
    HWCRYPTO_INPUT_LENGTH_ERR = -4,
    HWCRYPTO_MODE_ERR = -5,
    HWCRYPTO_ALIGNMENT_ERR = -6
} hwcrypto_err_t;

typedef enum {
    HWCRYPTO_ECB,
    HWCRYPTO_CBC,
    HWCRYPTO_CTR,
    HWCRYPTO_CFB,
    HWCRYPTO_CFB8
} hwcrypto_mode_t;

typedef enum {
    HWCRYPTO_MODE,
    HWCRYPTO_AES_KEY_ENC,
    HWCRYPTO_AES_KEY_DEC,
    HWCRYPTO_IV
} hwcrypto_opt_t;

typedef enum {
    HWCRYPTO_AES,
    HWCRYPTO_AES128,
    HWCRYPTO_AES256
} hwcrypto_cipher_t;

typedef struct {
    hwcrypto_cipher_t cipher;
    hwcrypto_mode_t mode;
    void *cipher_ctx;
} hwcrypto_cipher_ctx_t;

typedef struct {
    uint8_t __attribute__ ((aligned(4))) key[AES_MAX_KEY_SIZE];
    uint8_t __attribute__ ((aligned(4))) tmp[AES_BLOCK_SIZE];
    size_t key_length;
} hwcrypto_aes_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* HWCRYPTO_TYPES_H */
