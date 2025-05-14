/*
 * QEMU RDMA Backend: Utility helper functions
 *
 * Copyright (c) 2024 Bytedance
 *
 * Authors:
 *     zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "rdma/rdma-utils.h"

uint64_t _rdmadev_get_flags(uint64_t src, RdmadevFlags *flags, int size)
{
    uint64_t dst = 0;

    for (int idx = 0; idx < size; idx++) {
        if (src & flags[idx].src) {
            dst |= flags[idx].dst;
        }
    }

    return dst;
}

uint64_t _rdmadev_convert_type(uint64_t src, RdmadevFlags *flags, int size, uint64_t not_found)
{
    for (int idx = 0; idx < size; idx++) {
        if (src == flags[idx].src) {
            return flags[idx].dst;
        }
    }

    return not_found;
}

void rdmadev_addrconf_eui48(uint8_t *eui, const char *addr)
{
    memcpy(eui, addr, 3);
    eui[3] = 0xFF;
    eui[4] = 0xFE;
    memcpy(eui + 5, addr + 3, 3);
    eui[0] ^= 2;
}

