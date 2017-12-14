/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_sltb001a
 * @ingroup     drivers_periph_hwcrypto
 * @{
 *
 * @file
 * @brief       hwcrypto driver implementation
 *
 * @author      Max Breitenfeldt <max.breitenfeldt@fu-berlin.de>
 *
 * @}
 */
#define ENABLE_DEBUG  (1)
#include "debug.h"
#include "od.h"

#include <string.h>

#include "assert.h"
#include "em_cmu.h"
#include "em_crypto.h"
#include "em_device.h"
#include "mutex.h"
#include "periph/hwcrypto.h"
#include "periph/alt_hwcrypto.h"

#define AES_BLOCK_SIZE 16

static void _hwcrypto_prep(void);
static void _hwcrypto_done(void);

static mutex_t lock = MUTEX_INIT;

static void _aes_processloop(size_t length, CRYPTO_DataReg_TypeDef inReg, 
        uint32_t* in, CRYPTO_DataReg_TypeDef outReg, uint32_t* out)
{
  length /= AES_BLOCK_SIZE;
  CRYPTO->SEQCTRL = 16 << _CRYPTO_SEQCTRL_LENGTHA_SHIFT;

  while (length--)
  {
    /* Load data and trigger encryption */
    CRYPTO_DataWrite(inReg,(uint32_t*)in);

    CRYPTO->CMD = CRYPTO_CMD_SEQSTART;

    /* Save encrypted/decrypted data */
    CRYPTO_DataRead(outReg,(uint32_t*)out);

    out += 4;
    in  += 4;
  }
}

static int _aes_setkey_enc(hwcrypto_aes_ctx_t *ctx, const uint8_t *key,
        size_t key_length)
{
    assert(key_length == 16 || key_length == 32);
    ctx->key_length = key_length;

    memcpy(ctx->key, key, key_length);
    return 0;
}

static int _aes_setkey_dec(hwcrypto_aes_ctx_t *ctx, const uint8_t *key,
        size_t key_length)
{
    assert(key_length == 16 || key_length == 32);
    ctx->key_length = key_length;

    _hwcrypto_prep();
    switch (key_length) {
        case 16:
            CRYPTO_AES_DecryptKey128(CRYPTO, ctx->key, key);
            break;
        case 32:
            CRYPTO_AES_DecryptKey256(CRYPTO, ctx->key, key);
            break;
        default:
            break;
    }
    _hwcrypto_done();
    return 0;
}

int hwcrypto_cipher_init(hwcrypto_cipher_ctx_t *ctx, 
        hwcrypto_cipher_t cipher, void *cipher_ctx) {
    ctx->cipher = cipher;
    ctx->cipher_ctx = cipher_ctx;
    return 0;
}

int hwcrypto_cipher_set(hwcrypto_cipher_ctx_t *ctx, hwcrypto_opt_t option,
        const void *value, size_t length) {
   if (option == HWCRYPTO_MODE) {
       ctx->mode = *(hwcrypto_mode_t*)value;
       return 0;
   }
   if (option == HWCRYPTO_AES_KEY_ENC) {
       _aes_setkey_enc(ctx->cipher_ctx, (uint8_t*) value, length);
       return 0;
   }
   if (option == HWCRYPTO_AES_KEY_DEC) {
       _aes_setkey_dec(ctx->cipher_ctx, (uint8_t*) value, length);
       return 0;
   }
   return -1;
}

int hwcrypto_cipher_encrypt(hwcrypto_cipher_ctx_t *ctx, uint8_t *iv,
        const uint8_t *input, uint8_t *output, size_t length)
{
    assert(length != 0 && !(length & 0xf));

    if (ctx->cipher != HWCRYPTO_AES) {
        return -1;
    }
    hwcrypto_aes_ctx_t *aes_ctx = ctx->cipher_ctx;
    int err = 0;
    assert(!((int)aes_ctx->tmp & 0x3 || 
                (int)aes_ctx->key & 0x3 || 
                (int)iv & 0x3 ||
                (int)input & 0x3 || 
                (int)output & 0x3));

    _hwcrypto_prep();

    if (ctx->mode == HWCRYPTO_ECB) {
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_ECB128(CRYPTO, output, input, length, aes_ctx->key,true);
        } else {
            CRYPTO_AES_ECB256(CRYPTO, output, input, length, aes_ctx->key, true);
        }
        goto cleanup;
    }
    
    if (ctx->mode == HWCRYPTO_CBC) {
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_CBC128(CRYPTO, output, input, length, aes_ctx->key, 
                    iv,true);
        } else {
            CRYPTO_AES_CBC256(CRYPTO, output, input, length, aes_ctx->key, 
                    iv,true);
        }

        memcpy(iv, &output[length - 16], 16);
        goto cleanup;
    }

    if (ctx->mode == HWCRYPTO_CFB) {
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_CFB128(CRYPTO, output, input, length, aes_ctx->key, iv,true);
        } else {
            CRYPTO_AES_CFB256(CRYPTO, output, input, length, aes_ctx->key, iv,true);
        }

        memcpy(iv, &output[length - 16], 16);
        goto cleanup;
    }

    if (ctx->mode == HWCRYPTO_CTR) {
        if (aes_ctx->key_length == 16) {
            CRYPTO->CTRL = 0;
            CRYPTO->WAC = 0;
            CRYPTO->SEQCTRL = 0;
            CRYPTO->SEQCTRLB = 0;

            CRYPTO_KeyBufWrite(CRYPTO, (uint32_t*)aes_ctx->key, 8);
            CRYPTO_DataWrite(&CRYPTO->DATA1, (uint32_t*)iv);
            CRYPTO->CTRL |= CRYPTO_CTRL_INCWIDTH_INCWIDTH4;
            CRYPTO->SEQ0 = CRYPTO_CMD_INSTR_DATA1TODATA0  << _CRYPTO_SEQ0_INSTR0_SHIFT |
                CRYPTO_CMD_INSTR_AESENC        << _CRYPTO_SEQ0_INSTR1_SHIFT |
                CRYPTO_CMD_INSTR_DATA0TODATA3  << _CRYPTO_SEQ0_INSTR2_SHIFT |
                CRYPTO_CMD_INSTR_DATA1INC << _CRYPTO_SEQ0_INSTR3_SHIFT;
            CRYPTO->SEQ1 = CRYPTO_CMD_INSTR_DATA2TODATA0XOR << _CRYPTO_SEQ1_INSTR4_SHIFT;
            _aes_processloop(length, &CRYPTO->DATA2, (uint32_t*)input, &CRYPTO->DATA0, 
                    (uint32_t*)output);
            CRYPTO_DataRead(&CRYPTO->DATA1, (uint32_t*)iv);
            /*CRYPTO_AES_CTR128(CRYPTO, output, input, length, aes_ctx->key, */
                    /*iv, 0);*/
        } else {
            CRYPTO_AES_CTR256(CRYPTO, output, input, length, aes_ctx->key, 
                    iv, 0);
        }
        goto cleanup;
    }

    err = HWCRYPTO_MODE_ERR;

cleanup:
    _hwcrypto_done();
    return err;
}

int hwcrypto_cipher_decrypt(hwcrypto_cipher_ctx_t *ctx, uint8_t *iv,
        const uint8_t *input, uint8_t *output, size_t length)
{
    int err = 0;
    assert(length != 0 && !(length & 0xf));

    if (ctx->cipher != HWCRYPTO_AES) {
        return -1;
    }
    hwcrypto_aes_ctx_t *aes_ctx = ctx->cipher_ctx;
    assert(!((int)aes_ctx->tmp & 0x3 || 
                (int)aes_ctx->key & 0x3 || 
                (int)iv & 0x3 ||
                (int)input & 0x3 || 
                (int)output & 0x3));

    _hwcrypto_prep();

    if (ctx->mode == HWCRYPTO_ECB) {
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_ECB128(CRYPTO, output, input, length, aes_ctx->key,false);
        } else {
            CRYPTO_AES_ECB256(CRYPTO, output, input, length, aes_ctx->key, false);
        }
        goto cleanup;
    }

    if (ctx->mode == HWCRYPTO_CBC) {
        memcpy(aes_ctx->tmp, &input[length - 16], 16);
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_CBC128(CRYPTO, output, input, length, aes_ctx->key, iv,
                    false);
        } else {
            CRYPTO_AES_CBC256(CRYPTO, output, input, length, aes_ctx->key, iv,
                    false);
        }

        memcpy(iv, aes_ctx->tmp, 16);
        goto cleanup;
    }

    if (ctx->mode == HWCRYPTO_CFB) {
        memcpy(aes_ctx->tmp, &input[length - 16], 16);

        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_CFB128(CRYPTO, output, input, length, aes_ctx->key, iv,
                    false);
        } else {
            CRYPTO_AES_CFB256(CRYPTO, output, input, length, aes_ctx->key, iv,
                    false);
        }
        memcpy(iv, aes_ctx->tmp, 16);
        goto cleanup;
    }

    if (ctx->mode == HWCRYPTO_CTR) {
        if (aes_ctx->key_length == 16) {
            CRYPTO_AES_CTR128(CRYPTO, output, input, length, aes_ctx->key, iv, 0);
        } else {
            CRYPTO_AES_CTR256(CRYPTO, output, input, length, aes_ctx->key, iv, 0);
        }
        goto cleanup;
    }

    err = HWCRYPTO_MODE_ERR;

cleanup:
    _hwcrypto_done();
    return err;
}

static void _hwcrypto_prep(void)
{
    mutex_lock(&lock);
    CMU_ClockEnable(cmuClock_CRYPTO, true);
}

static void _hwcrypto_done(void)
{
    CMU_ClockEnable(cmuClock_CRYPTO, false);
    mutex_unlock(&lock);
}

static mutex_t alt_lock = MUTEX_INIT;


int alt_hwcrypto_cipher_init(alt_hwcrypto_ctx_t* ctx,
        hwcrypto_cipher_t cipher,
        hwcrypto_mode_t mode) {
    ctx->mode = mode;
    ctx->cipher = cipher;
    return 0;
}

int alt_hwcrypto_cipher_set(alt_hwcrypto_ctx_t *ctx, hwcrypto_opt_t option,
        const void *value, size_t length) {
    if (option == HWCRYPTO_AES_KEY_ENC) {
        CRYPTO_KeyBufWrite(CRYPTO, (uint32_t*)value, length / 2);
        return 0;
    }
    if (option == HWCRYPTO_IV) {
        CRYPTO_DataWrite(&CRYPTO->DATA1, (uint32_t*)value);
        return 0;
    }
    return -1;
}

int alt_hwcrypto_cipher_encrypt(alt_hwcrypto_ctx_t *ctx,
        const uint8_t *input, uint8_t *output, size_t length) {
    CRYPTO->CTRL = 0;
    CRYPTO->WAC = 0;
    if (ctx->cipher == HWCRYPTO_AES256) {
        CRYPTO->CTRL = CRYPTO_CTRL_AES_AES256;
    }
    if (ctx->mode == HWCRYPTO_CTR) {
        CRYPTO->CTRL |= CRYPTO_CTRL_INCWIDTH_INCWIDTH4;
        CRYPTO->SEQ0 = CRYPTO_CMD_INSTR_DATA1TODATA0  << _CRYPTO_SEQ0_INSTR0_SHIFT |
            CRYPTO_CMD_INSTR_AESENC        << _CRYPTO_SEQ0_INSTR1_SHIFT |
            CRYPTO_CMD_INSTR_DATA0TODATA3  << _CRYPTO_SEQ0_INSTR2_SHIFT |
            CRYPTO_CMD_INSTR_DATA1INC << _CRYPTO_SEQ0_INSTR3_SHIFT;
        CRYPTO->SEQ1 = CRYPTO_CMD_INSTR_DATA2TODATA0XOR << _CRYPTO_SEQ1_INSTR4_SHIFT;
        _aes_processloop(length, &CRYPTO->DATA2, (uint32_t*)input, &CRYPTO->DATA0, 
                (uint32_t*)output);
        // CRYPTO_DataRead(&CRYPTO->DATA1, (uint32_t*)iv);
    }
    return 0;
}

int alt_hwcrypto_acquire(void) {
    mutex_lock(&alt_lock);
    CMU_ClockEnable(cmuClock_CRYPTO, true);
    return 0;
}

int alt_hwcrypto_release(void) {
    CMU_ClockEnable(cmuClock_CRYPTO, false);
    mutex_unlock(&alt_lock);
    return 0;
}
