/*
 * QEMU VMW PVRDMA - QP implementation
 *
 * Copyright (C) 2018 Oracle
 * Copyright (C) 2018 Red Hat Inc
 * Copyright (C) 2024 Bytedance
 *
 * Authors:
 *     Yuval Shaia <yuval.shaia@oracle.com>
 *     Marcel Apfelbaum <marcel@redhat.com>
 *     zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "rdma/rdma.h"
#include "rdma/rdma-utils.h"
#include "pvrdma.h"
#include "pvrdma_verbs.h"

#include "trace.h"
#include "pvrdma-types.h"

static inline void pvrdma_free_wr(PVRDMADev *dev, RdmadevWc *wc)
{
    Rdmadev *rdev = dev->rdev;
    RdmadevSendWr *send_wr;
    int qp_type;

    /* destroy AH for UD/GSI */
    if (wc->opcode == RDMADEV_WC_SEND) {
        qp_type = rdmadev_qp_type(rdev, wc->qp_handle);
        assert((qp_type >= 0) && (qp_type < RDMADEV_QPT_MAX));

        if (qp_type == RDMADEV_QPT_UD || qp_type == RDMADEV_QPT_GSI) {
            send_wr = wc->wr;
            if (rdmadev_destroy_ah(rdev, send_wr->wr.ud.ah_handle) < 0) {
                pvrdma_error_report("Failed to destroy AH after UD send");
            }
        }
    }

    g_free(wc->wr);
}

void pvrdma_cq_complete(void *hwdev, RdmadevWc *wc, int cq, void *cq_ctx)
{
    PVRDMADev *dev = hwdev;
    PvrdmaRing *ring;
    struct pvrdma_cqe *cqe;
    struct pvrdma_cqne *cqne;

    /* Step #1: Put CQE on CQ ring */
    ring = cq_ctx;
    cqe = pvrdma_ring_rx_next(ring);
    if (unlikely(!cqe)) {
        pvrdma_error_report("CQ RX full");
        return;
    }

    memset(cqe, 0x00, sizeof(*cqe));
    cqe->wr_id = wc->wr_id;
    cqe->qp = wc->qp_handle;
    cqe->opcode = pvrdma_wc_opcode(wc->opcode);
    cqe->status = pvrdma_wc_status(wc->status);
    cqe->byte_len = wc->byte_len;
    cqe->imm_data = wc->ex.imm_data;
    cqe->src_qp = wc->remote_qp_handle;
    cqe->wc_flags = pvrdma_wc_flags(wc->wc_flags);
    cqe->pkey_index = wc->pkey_index;
    cqe->slid = wc->slid;
    cqe->sl = wc->sl;
    cqe->dlid_path_bits = wc->dlid_path_bits;
    cqe->port_num = 1;
    cqe->network_hdr_type = wc->network_hdr_type;

    pvrdma_ring_rx_inc(ring);

    /* Step #2: Put CQ number on dsr completion ring */
    ring = &dev->cq_ring;
    cqne = pvrdma_ring_rx_next(ring);
    if (unlikely(!cqe)) {
        pvrdma_error_report("DSR CQNE RX full");
        return;
    }

    cqne->info = cq;
    pvrdma_ring_rx_inc(ring);

    /* Step #3: Notify guest by the last vector: intrX */
    pvrdma_post_interrupt(dev, PVRDMA_MAX_INTERRUPTS - 1);

    trace_pvrdma_cq_complete(cq, rdmadev_wc_opcode(wc->opcode), wc->wr_id, wc->byte_len);

    /* Step #4: destroy context */
    pvrdma_free_wr(dev, wc);
}

static inline int pvrdma_post_send_rc(RdmadevSendWr *send_wr, struct pvrdma_sq_wqe_hdr *wqe)
{
    switch (wqe->opcode) {
    case PVRDMA_WR_SEND:
        break;

    case PVRDMA_WR_SEND_WITH_IMM:
        send_wr->ex.imm_data = wqe->ex.imm_data;
        break;

    case PVRDMA_WR_SEND_WITH_INV:
        send_wr->ex.invalidate_rkey = wqe->ex.invalidate_rkey;
        break;

    case PVRDMA_WR_RDMA_WRITE_WITH_IMM:
        send_wr->ex.imm_data = wqe->ex.imm_data;
        goto set_rdma;

    case PVRDMA_WR_RDMA_READ_WITH_INV:
        send_wr->ex.invalidate_rkey = wqe->ex.invalidate_rkey;
        goto set_rdma;

set_rdma:
    case PVRDMA_WR_RDMA_WRITE:
    case PVRDMA_WR_RDMA_READ:
        send_wr->wr.rdma.remote_addr = wqe->wr.rdma.remote_addr;
        send_wr->wr.rdma.rkey = wqe->wr.rdma.rkey;
        break;

    case PVRDMA_WR_ATOMIC_CMP_AND_SWP:
    case PVRDMA_WR_ATOMIC_FETCH_AND_ADD:
        send_wr->wr.atomic.remote_addr = wqe->wr.atomic.remote_addr;
        send_wr->wr.atomic.compare_add = wqe->wr.atomic.compare_add;
        send_wr->wr.atomic.swap = wqe->wr.atomic.swap;
        send_wr->wr.atomic.rkey = wqe->wr.atomic.rkey;
        break;

    case PVRDMA_WR_LOCAL_INV:
        send_wr->ex.invalidate_rkey = wqe->ex.invalidate_rkey;
        break;

    case PVRDMA_WR_MASKED_ATOMIC_CMP_AND_SWP:
    case PVRDMA_WR_MASKED_ATOMIC_FETCH_AND_ADD:
    default:
        pvrdma_error_report("Invalid opcode %d on send for RC", wqe->opcode);
        return -EINVAL;
    }

    return 0;
}

/* Address Vector information is carried by WQE, separate UD SEND/SEND-WITH-IMM
 * into 2 steps:
 * - create AH
 * - post send with AH handle
 * then free AH handle once CQ completion.
 */
static inline int pvrdma_post_send_ud(Rdmadev *rdev, RdmadevSendWr *send_wr, struct pvrdma_sq_wqe_hdr *wqe)
{
    struct pvrdma_av *av = &wqe->wr.ud.av;
    RdmadevAhAttr ah = { 0 };
    uint32_t pd_handle;
    int ret;

    switch (wqe->opcode) {
    case PVRDMA_WR_SEND:
        break;
    case PVRDMA_WR_SEND_WITH_IMM:
        send_wr->ex.imm_data = wqe->ex.imm_data;
        break;
    case PVRDMA_WR_SEND_WITH_INV:
        send_wr->ex.invalidate_rkey = wqe->ex.invalidate_rkey;
        break;
    default:
        pvrdma_error_report("Invalid opcode %d on send for UD", wqe->opcode);
        return -EINVAL;
    }

    QEMU_BUILD_BUG_ON(sizeof(av->dmac) != sizeof(av->dmac));
    memcpy(ah.dmac, av->dmac, sizeof(ah.dmac));
    ah.port_num = av->port_pd >> 24;
    ah.src_path_bits = av->src_path_bits;

    QEMU_BUILD_BUG_ON(sizeof(av->dgid) != sizeof(ah.grh.dgid.raw));
    memcpy(&ah.grh.dgid.raw, av->dgid, sizeof(av->dgid));
    ah.grh.sgid_index = av->gid_index;
    ah.grh.hop_limit = av->hop_limit;
    ah.grh.flow_label = av->sl_tclass_flowlabel & 0xfffff;
    ah.grh.traffic_class = av->sl_tclass_flowlabel >> 20;
    pd_handle = av->port_pd & 0xffffff;
    ret = rdmadev_create_ah(rdev, pd_handle, &ah, NULL);
    if (ret){
        pvrdma_error_report("Failed to create AH");
        return ret;
    }

    send_wr->wr.ud.remote_qpn = wqe->wr.ud.remote_qpn;
    send_wr->wr.ud.remote_qkey = wqe->wr.ud.remote_qkey;
    send_wr->wr.ud.ah_handle = ret;

    return 0;
}

static inline void pvrdma_fill_sge(RdmadevSge *rsge, struct pvrdma_sge *sge, uint32_t num_sge)
{
    RdmadevSge *_rsge;
    struct pvrdma_sge *_sge;

    for (uint32_t i = 0; i < num_sge; i++) {
        _rsge = &rsge[i];
        _sge = &sge[i];

        _rsge->addr = _sge->addr;
        _rsge->length = _sge->length;
        _rsge->lkey = _sge->lkey;
    }
}

void pvrdma_post_send(PVRDMADev *dev, uint32_t qp)
{
    Rdmadev *rdev = dev->rdev;
    PvrdmaRing *ring;
    struct pvrdma_ring *r;
    struct pvrdma_sq_wqe_hdr *wqe;
    RdmadevSendWr *send_wr;
    uint32_t idx;
    int qp_type;
    int ret;

    qp_type = rdmadev_qp_type(rdev, qp);
    if (qp_type < 0) {
        pvrdma_error_report("Failed to get QP(%x) type on post send", qp);
        return;
    }

    ret = rdmadev_qp_ctx(rdev, qp, (void **)&ring);
    if (ret) {
        pvrdma_error_report("Failed to get QP(%x) rings on post send", qp);
        return;
    }

    r = &ring->ring_state->tx;
    wqe = pvrdma_ring_cons_next(ring, r, &idx);
    while (wqe) {
        send_wr = g_malloc0(rdmadev_send_wr_size(wqe->num_sge));
	switch(qp_type) {
	case RDMADEV_QPT_RC:
            pvrdma_post_send_rc(send_wr, wqe);
            break;

	case RDMADEV_QPT_UD:
	case RDMADEV_QPT_GSI:
            pvrdma_post_send_ud(rdev, send_wr, wqe);
            break;

	default:
            /* print error message here only, let RDMA device handle this error */
            pvrdma_error_report("Failed to post-send on QP type %d", qp_type);
	}

        send_wr->wr_id = wqe->wr_id;
        send_wr->opcode = pvrdma_wr_opcode_to(wqe->opcode);
        send_wr->send_flags = pvrdma_send_flags_to(wqe->send_flags);
        send_wr->num_sge = wqe->num_sge;
        pvrdma_fill_sge(send_wr->sge, (struct pvrdma_sge *)&wqe[1], wqe->num_sge);
        trace_pvrdma_post_send(qp, rdmadev_wr_opcode(send_wr->opcode), wqe->wr_id);
        rdmadev_post_send(rdev, qp, send_wr);

        /* fetch next SQ WQE */
        pvrdma_ring_cons_inc(ring, r);
        wqe = pvrdma_ring_cons_next(ring, r, &idx);
    }
}

void pvrdma_post_recv(PVRDMADev *dev, uint32_t qp)
{
    Rdmadev *rdev = dev->rdev;
    PvrdmaRing *ring;
    struct pvrdma_ring *r;
    struct pvrdma_rq_wqe_hdr *wqe;
    RdmadevRecvWr *recv_wr;
    uint32_t idx;
    int ret;

    if (rdmadev_qp_is_srq(rdev, qp)) {
        pvrdma_error_report("post-recv fails on qp-handle %d: SRQ", qp);
        return;
    }

    ret = rdmadev_qp_ctx(rdev, qp, (void **)&ring);
    if (ret) {
        pvrdma_error_report("Failed to get QP(%x) rings on post send", qp);
        return;
    }

    ring = &ring[1];
    r = &ring->ring_state->rx;
    wqe = pvrdma_ring_cons_next(ring, r, &idx);
    while (wqe) {
        recv_wr = g_malloc0(rdmadev_recv_wr_size(wqe->num_sge));
        recv_wr->wr_id = wqe->wr_id;
        recv_wr->num_sge = wqe->num_sge;
        pvrdma_fill_sge(recv_wr->sge, (struct pvrdma_sge *)&wqe[1], wqe->num_sge);
        rdmadev_post_recv(rdev, qp, recv_wr);
        trace_pvrdma_post_recv(qp, wqe->wr_id);

        /* fetch next RQ WQE */
        pvrdma_ring_cons_inc(ring, r);
        wqe = pvrdma_ring_cons_next(ring, r, &idx);
    }
}

void pvrdma_post_srq_recv(PVRDMADev *dev, uint32_t srq_handle)
{
#if 0
    Rdmadev *rdev = dev->rdev;
    RdmadevSrq *srq;
    PvrdmaRing *ring;
    struct pvrdma_ring *r;
    struct pvrdma_rq_wqe_hdr *wqe;
    RdmadevRecvWr *recv_wr;
    uint32_t idx;

    srq = rdmadev_get_srq(rdev, srq_handle);
    if (!srq) {
        pvrdma_error_report("Invalid srq-handle %d on post-recv", srq_handle);
        return;
    }

    ring = srq->opaque;
    r = &ring->ring_state->rx;
    wqe = pvrdma_ring_cons_next(ring, r, &idx);
    while (wqe) {
    printf("POST SRQ RECV: ring %s, max %d, tail %d head %d, wqe %p, wqe->wr_id %lx, idx %d\n", ring->name, ring->max_elems, qatomic_read(&r->prod_tail), qatomic_read(&r->cons_head), wqe, wqe->wr_id, idx);

        recv_wr = g_malloc0(rdmadev_recv_wr_size(wqe->num_sge));
        recv_wr->wr_id = wqe->wr_id;
        recv_wr->num_sge = wqe->num_sge;
        pvrdma_fill_sge(recv_wr->sge, (struct pvrdma_sge *)&wqe[1], wqe->num_sge);
        rdmadev_post_srq_recv(rdev, srq_handle, recv_wr);

        pvrdma_ring_cons_inc(ring, r);
        wqe = pvrdma_ring_cons_next(ring, r, &idx);
    }
#endif
}
