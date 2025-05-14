/*
 * QEMU RDMA Backend Support.
 *
 * Copyright (c) 2024 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_RDMADEV_H
#define RDMA_RDMADEV_H

#include "qemu/error-report.h"
#include "rdma/rdma-types.h"
#include "rdma/rdma.h"

#define rdmadev_error_report(rdev, fmt, ...) \
    error_report("RDMA %s: " fmt, rdmadev_name(rdev), ## __VA_ARGS__)
#define rdmadev_warn_report(rdev, fmt, ...) \
    warn_report("RDMA %s: " fmt, rdmadev_name(rdev), ## __VA_ARGS__)
#define rdmadev_info_report(rdev, fmt, ...) \
    info_report("RDMA %s: " fmt, rdmadev_name(rdev), ## __VA_ARGS__)

#endif
