/*
 * QEMU RDMA Backend Support for RoCE device.
 *
 * Copyright (c) 2024 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_ROCEDEV_H
#define RDMA_ROCEDEV_H

#include "qemu/error-report.h"
#include "rdma/rdma-types.h"
#include "roce/roce.h"

#define rocedev_error_report(rocedev, fmt, ...) \
    error_report("RoCE %s: " fmt, rdmadev_name(&rocedev->rdev), ## __VA_ARGS__)
#define rocedev_warn_report(rocedev, fmt, ...) \
    warn_report("RoCE %s: " fmt, rdmadev_name(&rocedev->rdev), ## __VA_ARGS__)
#define rocedev_info_report(rocedev, fmt, ...) \
    info_report("RoCE %s: " fmt, rdmadev_name(&rocedev->rdev), ## __VA_ARGS__)

#define ROCEDEV_MAX_PORT 1

#define TYPE_ROCEDEV "rdmadev-roce"

OBJECT_DECLARE_SIMPLE_TYPE(Rocedev, ROCEDEV)

struct Rocedev {
    Rdmadev rdev;
    NICState *nic;

    roce_ctx ctx;
};

#endif /* RDMA_ROCEDEV_H */
