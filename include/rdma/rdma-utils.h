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

#ifndef RDMA_UTILS_H
#define RDMA_UTILS_H

#include "qemu/osdep.h"

typedef struct RdmadevFlags {
    uint64_t src;
    uint64_t dst;
} RdmadevFlags;

/**
 * _rdmadev_get_flags:
 * @src: flag of bits.
 * @flags: table of src/dst flag bit mapping.
 * @size: array size of flags.
 *
 * convert flags from @src to @dst. Ex, src flags set: A, B, C
 * dst flags set: X, Y, Z. Then _rdmadev_get_flags(A | C, ) returns
 * (X | Z).
 */
uint64_t _rdmadev_get_flags(uint64_t src, RdmadevFlags *flags, int size);

#define rdmadev_get_flags(src, flags) \
            _rdmadev_get_flags(src, flags, ARRAY_SIZE(flags))

/**
 * _rdmadev_convert_type:
 * @src: source type.
 * @flags: table of src/dst flag bit mapping.
 * @size: array size of flags.
 * @not_found: return value on not found.
 *
 * convert type from @src to @dst. Ex, src flags set: A, B, C
 * dst flags set: X, Y, Z. Then _rdmadev_convert_type(B, ) returns Y.
 */
uint64_t _rdmadev_convert_type(uint64_t src, RdmadevFlags *flags, int size, uint64_t not_found);

#define rdmadev_convert_type(src, flags, not_found) \
            _rdmadev_convert_type(src, flags, ARRAY_SIZE(flags), not_found)

/**
 * rdmadev_addrconf_eui48:
 * @eui: 48-bit Extended Unique Identifier
 * @addr: MAC address
 *
 * convert MAC addr to EUI48 format.
 */
void rdmadev_addrconf_eui48(uint8_t *eui, const char *addr);

#endif
