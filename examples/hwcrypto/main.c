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
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "shell.h"
#include "msg.h"

extern int hwcrypto_cmd(int argc, char **argv);
extern int ctr_benchmark_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "hwcrypto", "Run hwcrypto benchmark", hwcrypto_cmd },
    { "ctr_benchmark", "Run AES128 CTR encryption benchmark", ctr_benchmark_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    puts("RIOT hwcrypto benchmark application");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
