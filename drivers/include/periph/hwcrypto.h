/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    drivers_periph_hwcrypto Hardware Crypto
 * @ingroup     drivers_periph
 * @brief       Low-level cryptography accelerator driver
 *
 * @{
 * @file
 * @brief       Low-level Cryptograpy peripheral driver interface definitions
 *
 * @author      Max Breitenfeldt <max.breitenfeldt@fu-berlin.de>
 */

#ifndef HWCRYPTO_H
#define HWCRYPTO_H

#include "periph_cpu.h"
#include "hwcrypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int hwcrypto_cipher_init(hwcrypto_cipher_ctx_t *ctx, 
        hwcrypto_cipher_t cipher, void *cipher_ctx);

int hwcrypto_cipher_set(hwcrypto_cipher_ctx_t *ctx, hwcrypto_opt_t option,
        const void *value, size_t length);

int hwcrypto_cipher_encrypt(hwcrypto_cipher_ctx_t *ctx, uint8_t *iv,
        const uint8_t *input, uint8_t *output, size_t length); 
int hwcrypto_cipher_decrypt(hwcrypto_cipher_ctx_t *ctx, uint8_t *iv,
        const uint8_t *input, uint8_t *output, size_t length); 

#ifdef __cplusplus
}
#endif

#endif /* HWCRYPTO_H */
/** @} */
