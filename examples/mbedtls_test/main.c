/*
 * Copyright (C) 2017 Max Breitenfeld <max.breitenfeldt@fu-berlin.de>
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
 * @brief       mbedtls example application
 *
 * @author      Max Breitenfeld <max.breitenfeldt@fu-berlin.de>
 * @}
 */
#include <stdio.h>

#include "mbedtls/aes.h"

#include "periph/hwcrypto.h"

#include "em_crypto.h"
#include "em_cmu.h"

#include "od.h"
#include "xtimer.h"

int main(void)
{
    printf("Mbedtls Self Test\n");
    mbedtls_aes_self_test(1);
}
