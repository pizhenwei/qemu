/*
 * QEMU RDMA Backend Support for host IB device.
 *
 * Copyright (c) 2024 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_IBDEV_H
#define RDMA_IBDEV_H

#include "qemu/error-report.h"
#include "rdma/rdma-types.h"
#include "contrib/rdmacm-mux/rdmacm-mux.h"

#define ibdev_error_report(fmt, ...) \
    error_report("%s: " fmt, "ibdev", ## __VA_ARGS__)
#define ibdev_warn_report(fmt, ...) \
    warn_report("%s: " fmt, "ibdev", ## __VA_ARGS__)
#define ibdev_info_report(fmt, ...) \
    info_report("%s: " fmt, "ibdev", ## __VA_ARGS__)

#define IBDEV_MAX_PORT 1

typedef struct IbdevUc{
    RdmadevUc ruc;
} IbdevUc;

typedef struct IbdevPd {
    RdmadevPd rpd;
    struct ibv_pd *ibpd;
} IbdevPd;

typedef struct IbdevCq {
    RdmadevCq rcq;
    struct ibv_cq *ibcq;
} IbdevCq;

typedef struct IbdevCqe {
    uint8_t unused;
} IbdevCqe;

#define IBDEV_DMA_MR_KEY 0xFFFFFFFF
typedef struct IbdevMr {
    RdmadevMr rmr;
    void *buffer;
    struct ibv_mr *ibmr;
} IbdevMr;

typedef struct IbdevQp {
    RdmadevQp rqp;
    struct ibv_qp *ibqp;
} IbdevQp;

typedef struct IbdevSrq {
    RdmadevSrq srq;
    struct ibv_srq *ibsrq;
} IbdevSrq;

typedef struct IbdevAh {
    RdmadevAh rah;
    struct ibv_ah_attr ibah_attr;
    struct ibv_ah *ibah;
    union ibv_gid sgid;
} IbdevAh;

typedef struct IbdevGsiRecvWr {
    QTAILQ_ENTRY(IbdevGsiRecvWr) next;
    RdmadevRecvWr *wr;
} IbdevGsiRecvWr;

#define TYPE_IBDEV "rdmadev-ibdev"

OBJECT_DECLARE_SIMPLE_TYPE(Ibdev, IBDEV)

struct Ibdev {
    Rdmadev rdev;

    CharBackend mad;
    int mad_can_receive;

    struct ibv_device *ibv_dev;
    struct ibv_context *ibv_ctx;
    struct ibv_comp_channel *ibv_chan;

    /* There is no ibv QP for GSI. ibv_query_qp for other QPs */
    struct ibv_qp_attr gsi_attr;
    IbdevCq *gsi_send_cq;
    IbdevCq *gsi_recv_cq;
    QTAILQ_HEAD(, IbdevGsiRecvWr) gsi_recv_wrs;

    /* Incoming message from rdmacm-mux */
    RdmaCmMuxMsg in_msg;
    int in_msg_size;
};

int ibdev_add_gid(Rdmadev *rdev, RdmaPortAttr *port, RdmaGid *gid);
int ibdev_del_gid(Rdmadev *rdev, RdmaPortAttr *port, RdmaGid *gid);
int ibdev_get_gid(Rdmadev *rdev, RdmaPortAttr *port, uint8_t gid_index, union ibv_gid *sgid);
int ibdev_post_send_gsi(Rdmadev *rdev, RdmadevQp *qp, RdmadevSendWr *send_wr);
int ibdev_mux_can_receive(void *opaque);
void ibdev_mux_read(void *opaque, const uint8_t *buf, int size);

#endif
