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

#ifndef ALT_HWCRYPTO_H
#define ALT_HWCRYPTO_H

#include "periph_cpu.h"
#include "hwcrypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    hwcrypto_cipher_t cipher;
    hwcrypto_mode_t mode;
} alt_hwcrypto_ctx_t;

int alt_hwcrypto_cipher_init(alt_hwcrypto_ctx_t* ctx,
        hwcrypto_cipher_t cipher,
        hwcrypto_mode_t mode);
int alt_hwcrypto_cipher_set(alt_hwcrypto_ctx_t *ctx, hwcrypto_opt_t option,
        const void *value, size_t length);

int alt_hwcrypto_cipher_encrypt(alt_hwcrypto_ctx_t *ctx,
        const uint8_t *input, uint8_t *output, size_t length);

int alt_hwcrypto_acquire(void);
int alt_hwcrypto_release(void);
#ifdef __cplusplus
}
#endif

#endif /* ALT_HWCRYPTO_H */
/** @} */
