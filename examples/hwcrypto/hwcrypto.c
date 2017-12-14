/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Demonstrating the sending and receiving of UDP data
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/aes.h"

#include "periph/hwcrypto.h"
#include "periph/alt_hwcrypto.h"
#include "timex.h"
#include "xtimer.h"

#include "em_device.h"
#include "em_crypto.h"
#include "em_cmu.h"

#define MAX_BUF_SIZE 2048
#define MAX_KEY_SIZE 32

static uint8_t __attribute__ ((aligned(4))) buf[MAX_BUF_SIZE] = {0};
static uint8_t __attribute__ ((aligned(4))) iv[16] = {0};
static uint8_t __attribute__ ((aligned(4))) key[MAX_KEY_SIZE] = {0};

void usage(void)
{
    puts("hwcrypto [op] [mode] [key size] [n] [loop]");
    puts("Options:\n");
    puts("op: enc, dec");
    puts("mode: ecb, cbc, cfb, ctr");
    puts("key size: 128, 256");
    puts("n: number of blocks");
    puts("loop: number of calls");
}

uint32_t hw_benchmark(bool encrypt, hwcrypto_mode_t mode, size_t key_length,
        size_t n_blocks, int n_loop)
{
    uint32_t start, stop;
    hwcrypto_cipher_ctx_t cipher_ctx;
    hwcrypto_aes_ctx_t aes_ctx;

    hwcrypto_opt_t tmp_opt;
    if (encrypt || mode == HWCRYPTO_CFB) {
        tmp_opt = HWCRYPTO_AES_KEY_ENC;
    } else {
        tmp_opt = HWCRYPTO_AES_KEY_DEC;
    }
    start = xtimer_now_usec();
    hwcrypto_cipher_init(&cipher_ctx, HWCRYPTO_AES, &aes_ctx);
    hwcrypto_cipher_set(&cipher_ctx, HWCRYPTO_MODE, &mode, 0);
    hwcrypto_cipher_set(&cipher_ctx, tmp_opt, key, key_length);

    if (encrypt) {
        for (int i = 0; i < n_loop; i++) {
            hwcrypto_cipher_encrypt(&cipher_ctx, iv, buf, buf, n_blocks * 16);
        }
    } else {
        for (int i = 0; i < n_loop; i++) {
            hwcrypto_cipher_decrypt(&cipher_ctx, iv, buf, buf, n_blocks * 16);
        }
    }
    stop = xtimer_now_usec();

    return stop - start;

}

uint32_t sw_benchmark(bool encrypt, hwcrypto_mode_t mode, size_t key_length,
        size_t n_blocks, int n_loop)
{
    mbedtls_aes_context mbed_ctx;
    int mbed_op = encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
    size_t iv_off = 0;
    int i, j;

    uint32_t start = xtimer_now_usec();
    if (encrypt || mode == HWCRYPTO_CFB) {
        mbedtls_aes_setkey_enc(&mbed_ctx, key, key_length * 8);
    } else {
        mbedtls_aes_setkey_dec(&mbed_ctx, key, key_length * 8);
    }

    if (mode == HWCRYPTO_ECB) {
        for (i = 0; i < n_loop; i++) {
            for (j = 0; j < n_blocks * 16; j += 16) {
                mbedtls_aes_crypt_ecb(&mbed_ctx, mbed_op, buf + j, buf + j);
            }
        }
    }
    if (mode == HWCRYPTO_CBC) {
        for (i = 0; i < n_loop; i++) {
            mbedtls_aes_crypt_cbc(&mbed_ctx, mbed_op, n_blocks * 16, iv, buf, buf);
        }
    }
    if (mode == HWCRYPTO_CFB) {
        for (i = 0; i < n_loop; i++) {
            mbedtls_aes_crypt_cfb128(&mbed_ctx, mbed_op, n_blocks * 16, &iv_off, iv, buf, buf);
        }
    }
    if (mode == HWCRYPTO_CTR) {
        static uint8_t tmp[16] = {0};
        for (i = 0; i < n_loop; i++) {
            mbedtls_aes_crypt_ctr(&mbed_ctx, n_blocks * 16, &iv_off, iv, tmp, buf, buf);
        }
    }
    return xtimer_now_usec() - start;
}

uint32_t em_benchmark_ctr(size_t n_blocks, int n_loop) {
    uint32_t start = xtimer_now_usec();
    int i;
    CMU_ClockEnable(cmuClock_CRYPTO, true);
    for (i = 0; i < n_loop; i++) {
        CRYPTO_AES_CTR128(CRYPTO, buf, buf, n_blocks * 16, key, iv, 0);
        //memcpy(iv, &buf[buf_size - 16], 16);
    }
    CMU_ClockEnable(cmuClock_CRYPTO, false);
    return xtimer_now_usec() - start;
}

uint32_t alt_hw_benchmark_ctr(size_t n_blocks, int n_loop) {
    alt_hwcrypto_ctx_t alt_ctx;
    uint32_t start = xtimer_now_usec();
    alt_hwcrypto_acquire();
    alt_hwcrypto_cipher_init(&alt_ctx, HWCRYPTO_AES128, HWCRYPTO_CTR);
    alt_hwcrypto_cipher_set(&alt_ctx, HWCRYPTO_AES_KEY_ENC, key, 16);
    alt_hwcrypto_cipher_set(&alt_ctx, HWCRYPTO_IV, iv, 16);
    for (int i = 0; i < n_loop; i++) {
        alt_hwcrypto_cipher_encrypt(&alt_ctx, buf, buf, n_blocks * 16);
    }
    alt_hwcrypto_release();
    return xtimer_now_usec() - start;
}

int ctr_benchmark_cmd(int argc, char **argv)
{
    const int REPS = 10;
    const int MAX_BLOCKS = 64;
    puts("AES128-CTR benchmark");
    int n_loop;
    uint32_t alt_hwtime, emtime, swtime, hwtime;
    if (argc == 2) {
        n_loop = atoi(argv[1]);
    } else {
        n_loop = 1;
    }
    printf("repetitions: %d, max_blocks: %d, n_loop: %d\n", REPS, MAX_BLOCKS, n_loop);
    puts("alt_hwcrypto, emlib, mbedtls, hwcrypto");
    for (int i = 1; i <= MAX_BLOCKS; i++) {
        alt_hwtime = 0;
        emtime = 0;
        swtime = 0;
        hwtime = 0;
        for (int j = 0; j < REPS; j++) {
            alt_hwtime += alt_hw_benchmark_ctr(i, n_loop);
            emtime += em_benchmark_ctr(i, n_loop);
            swtime += sw_benchmark(true, HWCRYPTO_CTR, 16, i, n_loop);
            hwtime += hw_benchmark(true, HWCRYPTO_CTR, 16, i, n_loop);
        }
        printf("%d,", i);
        printf("%ld,", alt_hwtime);
        printf("%ld,", emtime);
        printf("%ld,", swtime);
        printf("%ld", hwtime);
        printf("\n");
    }
    return 0;
}

int hwcrypto_cmd(int argc, char **argv)
{
    if (argc < 5) {
        usage();
        return 1;
    }

    int key_size = atoi(argv[3]);
    if (!(key_size == 128 || key_size == 256)){
        puts("invalid key size");
        return 1;
    }
    key_size /= 8;

    size_t n_blocks = atoi(argv[4]);
    if (n_blocks * 16 > MAX_BUF_SIZE) {
        puts("not enough memory");
        return 1;
    }
    int n_loop = atoi(argv[5]);

    char *mode = argv[2];
    char *op = argv[1];

    hwcrypto_mode_t mode_tmp;
    if (!strcmp(mode, "ecb")) {
        mode_tmp = HWCRYPTO_ECB;
    }
    if (!strcmp(mode, "cbc")) {
        mode_tmp = HWCRYPTO_CBC;
    }
    if (!strcmp(mode, "cfb")) {
        mode_tmp = HWCRYPTO_CFB;
    }
    if (!strcmp(mode, "ctr")) {
        mode_tmp = HWCRYPTO_CTR;
    }

    bool encrypt = (!strcmp(op, "enc")) ? true : false;

    hw_benchmark(encrypt, mode_tmp, key_size, 1, 1);

    uint32_t hwtime = hw_benchmark(encrypt, mode_tmp, key_size, n_blocks, n_loop);
    uint32_t swtime = sw_benchmark(encrypt, mode_tmp, key_size, n_blocks, n_loop);
    float speedup = swtime / (float) hwtime;

    /* Print results */
    printf("op: %s, mode: %s, keysize: %d, blocks: %d, loops: %d\n\
hwtime: %ld, swtime: %ld, speedup: %f",
            op, mode, key_size * 8, n_blocks, n_loop, hwtime, swtime, speedup);

    /* optional benchmarks */
    if (mode_tmp == HWCRYPTO_CTR && encrypt && key_size == 16) {
        printf(", emtime: %ld", em_benchmark_ctr(n_blocks, n_loop));
        printf(", alt_hwtime: %ld", alt_hw_benchmark_ctr(n_blocks, n_loop));
    }

    printf("\n");
    return 0;
}
