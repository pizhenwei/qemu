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
#include "qemu/osdep.h"

#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "qemu/iov.h"
#include "qemu/memalign.h"
#include "qapi/error.h"
#include "qapi/qapi-visit-rdma.h"
#include "qapi/visitor.h"
#include "rdma/rdma.h"
#include "rocedev.h"
#include "../rdmadev.h"
#include "rocedev-types.h"

static void rocedev_log(void *ctx_opaque, char *msg)
{
    Rocedev *rocedev = ctx_opaque;

    rocedev_error_report(rocedev, "%s", msg);
}

static void rocedev_net_xmit(void *ctx_opaque, uint16_t queue, struct iovec *iovs, uint32_t num_iov)
{
    Rocedev *rocedev = ctx_opaque;
    NetClientState *nc = qemu_get_subqueue(rocedev->nic, queue);

    qemu_sendv_packet_async(nc, iovs, num_iov, NULL);
}

static int rocedev_cq_comp(void *ctx_opaque, roce_wc *_wc, int cq, void *opaque)
{
    Rocedev *rocedev = ctx_opaque;
    Rdmadev *rdev = &rocedev->rdev;
    RdmadevWc wc = { 0 };

    if (_wc->opcode == ROCE_WC_RECV || _wc->opcode == ROCE_WC_RECV_RDMA_WITH_IMM) {
        RdmadevRecvWr *recv_wr = (RdmadevRecvWr *)_wc->wr_id;
        wc.wr_id = recv_wr->wr_id;
    } else {
        RdmadevSendWr *send_wr = (RdmadevSendWr *)_wc->wr_id;
        wc.wr_id = send_wr->wr_id;
    }
    wc.qp_handle = _wc->local_qpn;
    wc.remote_qp_handle = _wc->remote_qpn;
    wc.byte_len = _wc->byte_len;
    wc.wc_flags = rocedev_wc_flags_to(_wc->wc_flags);
    wc.ex.imm_data = _wc->imm_data;
    wc.opcode = rocedev_wc_opcode_to(_wc->opcode);
    wc.status = rocedev_wc_status_to(_wc->status);
    wc.pkey_index = _wc->pkey_index;
    wc.slid = 0;
    wc.sl = 0;
    wc.dlid_path_bits = 0;
    wc.wr = (void *)_wc->wr_id;

    rdev->cq_comp(rdev->hwdev, &wc, cq, opaque);

    return 0;
}

static void *rocedev_dma_map(void *ctx_opaque, uint64_t hwaddr, uint32_t len)
{
    Rocedev *rocedev = ctx_opaque;

    return rocedev->rdev.dma_map(rocedev->rdev.hwdev, hwaddr, len);
}

static void rocedev_dma_unmap(void *ctx_opaque, void *addr, uint32_t len)
{
    Rocedev *rocedev = ctx_opaque;

    return rocedev->rdev.dma_unmap(rocedev->rdev.hwdev, addr, len);
}

static int rocedev_spin_init(void *lock, int shared)
{
    qemu_spin_init(lock);

    return 0;
}

static int rocedev_spin_lock(void *lock)
{
    qemu_spin_lock(lock);

    return 0;
}

static int rocedev_spin_trylock(void *lock)
{
    return qemu_spin_trylock(lock);
}

static int rocedev_spin_unlock(void *lock)
{
    qemu_spin_unlock(lock);

    return 0;
}

static int rocedev_new_ctx(Rocedev *rocedev)
{
    roce_ctx_para para = { 0 };

    if (rocedev->rdev.dev.u.roce.version == RDMADEV_ROCE_TYPE_ROCE_V1) {
        para.version = ROCE_V1;
    } else if (rocedev->rdev.dev.u.roce.version == RDMADEV_ROCE_TYPE_ROCE_V2) {
        para.version = ROCE_V2;
    }

    para.ctx_opaque = rocedev;
    para.page_size = qemu_target_page_size();
    para.log_level = roce_log_error;
    para.log = rocedev_log;
    para.net_xmit = rocedev_net_xmit;
    para.cq_comp = rocedev_cq_comp;
    para.dma_map = rocedev_dma_map;
    para.dma_unmap = rocedev_dma_unmap;
    para.malloc = g_malloc;
    para.free = g_free;
    para.calloc = g_malloc0_n;
    para.realloc = g_realloc;
    para.lock_size = sizeof(QemuSpin);
    para.spin_init = rocedev_spin_init;
    para.spin_lock = rocedev_spin_lock;
    para.spin_trylock = rocedev_spin_trylock;
    para.spin_unlock = rocedev_spin_unlock;

    rocedev->ctx = roce_new_ctx(&para);
    if (!rocedev->ctx) {
        return -ENODEV;
    }

    return 0;
}

static int rocedev_init_roce(Rocedev *rocedev)
{
    RdmaDevAttr *dev_attr = &rocedev->rdev.dev_attr;
    roce_device_attr attr = { 0 };

    attr.max_uc = dev_attr->max_uc;
    attr.max_mr_size = dev_attr->max_mr_size;
    attr.max_qp = dev_attr->max_qp;
    attr.max_qp_wr = dev_attr->max_qp_wr;
    attr.max_sge = dev_attr->max_sge;
    attr.max_sge_rd = dev_attr->max_sge_rd;
    attr.max_cq = dev_attr->max_cq;
    attr.max_cqe = dev_attr->max_cqe;
    attr.max_mr = dev_attr->max_mr;
    attr.max_pd = dev_attr->max_pd;
    attr.max_qp_rd_atom = dev_attr->max_qp_rd_atom;
    attr.max_ee_rd_atom = dev_attr->max_ee_rd_atom;
    attr.max_res_rd_atom = dev_attr->max_res_rd_atom;
    attr.max_qp_init_rd_atom = dev_attr->max_qp_init_rd_atom;
    attr.max_ee_init_rd_atom = dev_attr->max_ee_init_rd_atom;
    attr.max_ee = dev_attr->max_ee;
    attr.max_rdd = dev_attr->max_rdd;
    attr.max_mw = dev_attr->max_mw;
    attr.max_raw_ipv6_qp = dev_attr->max_raw_ipv6_qp;
    attr.max_raw_ethy_qp = dev_attr->max_raw_ethy_qp;
    attr.max_mcast_grp = dev_attr->max_mcast_grp;
    attr.max_mcast_qp_attach = dev_attr->max_mcast_qp_attach;
    attr.max_total_mcast_qp_attach = dev_attr->max_total_mcast_qp_attach;
    attr.max_ah = dev_attr->max_ah;
    attr.max_fmr = dev_attr->max_fmr;
    attr.max_map_per_fmr = dev_attr->max_map_per_fmr;
    //TODO attr.max_srq = dev_attr->max_srq;
    attr.max_srq_wr = dev_attr->max_srq_wr;
    attr.max_srq_sge = dev_attr->max_srq_sge;
    attr.max_inline_data = dev_attr->max_inline_data;
    attr.max_pkeys = dev_attr->max_pkeys;
    attr.local_ca_ack_delay = dev_attr->local_ca_ack_delay;
    attr.phys_port_cnt = dev_attr->phys_port_cnt;

    return roce_init_device(rocedev->ctx, &attr);
}

static int rocedev_init_dev(Rdmadev *rdev)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    int ret;

    ret = rocedev_new_ctx(rocedev);
    if (ret) {
        return ret;
    }

    ret = rocedev_init_roce(rocedev);
    if (ret) {
        goto free_ctx;
    }

    return 0;

free_ctx:
    roce_free_ctx(rocedev->ctx);
    return ret;
}

static void rocedev_finalize_dev(Rdmadev *rdev)
{
    Rocedev *rocedev = ROCEDEV(rdev);

    roce_free_ctx(rocedev->ctx);
}

static int rocedev_net_recv(NetClientState *nc, const struct iovec *iov, int iovcnt, void *opaque)
{
    Rocedev *rocedev = opaque;

    return roce_net_recv(rocedev->ctx, nc->queue_index, iov, iovcnt);
}

static int rocedev_init_port(Rdmadev *rdev, RdmaPortAttr *port, NICState *nic)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_port_attr attr = { 0 };
    NetClientState *nc = qemu_get_queue(nic);
    int vnet_hdr_len;
    int ret;

    attr.max_mtu = 1024;
    attr.active_mtu = 1024;
    attr.max_msg_sz = port->max_msg_sz;
    ret = roce_init_port(rocedev->ctx, port->index, &attr);
    if (ret) {
        return ret;
    }

    roce_set_port_mac(rocedev->ctx, 1, nic->conf->macaddr.a);
    if (qemu_has_vnet_hdr(nc->peer)) {
        vnet_hdr_len = qemu_get_vnet_hdr_len(nc->peer);
        ret = roce_set_port_vnet(rocedev->ctx, port->index, vnet_hdr_len);
        if (ret) {
            return ret;
        }
    }

    rocedev->nic = nic;
    nic->recv_roce = rocedev_net_recv;
    nic->roce_opaque = rocedev;

    return 0;
}

static void rocedev_finalize_port(Rdmadev *rdev, uint8_t port)
{
}

static int rocedev_query_port(Rdmadev *rdev, uint8_t port, RdmaPortAttr *_attr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_port_attr attr;
    int ret;

    ret = roce_query_port(rocedev->ctx, port, &attr);
    if (ret) {
        return ret;
    }

    _attr->port_cap_flags = rocedev_port_cap_to(attr.port_cap_flags);
    _attr->max_mtu = rocedev_mtu_to(attr.max_mtu);
    _attr->active_mtu = rocedev_mtu_to(attr.active_mtu);
    _attr->gid_tbl_len = attr.gid_tbl_len;
    _attr->pkey_tbl_len = attr.pkey_tbl_len;
    _attr->max_msg_sz = attr.max_msg_sz;
    _attr->bad_pkey_cntr = attr.bad_pkey_cntr;
    _attr->qkey_viol_cntr = attr.qkey_viol_cntr;
    _attr->link_layer = RDMADEV_LINK_LAYER_ETHERNET;
    _attr->active_speed = RDMADEV_SPEED_5GBPS;
    _attr->max_vl_num = 1;

    return 0;
}

static int rocedev_add_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid, RdmaGidType type)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    RdmaRoceType version = rdev->dev.u.roce.version;

    if ((version == RDMADEV_ROCE_TYPE_ROCE_V1) &&
       (type != RDMADEV_GID_TYPE_ROCE_V1)) {
        return -ENOTSUP;
    } else if ((version == RDMADEV_ROCE_TYPE_ROCE_V2) &&
       (type != RDMADEV_GID_TYPE_ROCE_V2)) {
        return -ENOTSUP;
    }

    return roce_add_gid(ctx, port, index, gid);
}

static int rocedev_del_gid(Rdmadev *rdev, uint8_t port, uint8_t index)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    return roce_del_gid(ctx, port, index);
}

static int rocedev_get_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    return roce_get_gid(ctx, port, index, gid);
}

static int rocedev_alloc_uc(Rdmadev *rdev, int uc, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    return roce_alloc_uc(ctx, uc, opaque);
}

static int rocedev_dealloc_uc(Rdmadev *rdev, int uc)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(uc >= 0);
    return roce_dealloc_uc(ctx, uc);
}

static int rocedev_alloc_pd(Rdmadev *rdev, int uc, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    return roce_alloc_pd(ctx, uc, opaque);
}

static int rocedev_dealloc_pd(Rdmadev *rdev, int pd)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(pd >= 0);
    return roce_dealloc_pd(ctx, pd);
}

static int rocedev_create_cq(Rdmadev *rdev, int uc, int cqe, int comp_vector, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    return roce_create_cq(ctx, uc, cqe, comp_vector, opaque);
}

static int rocedev_destroy_cq(Rdmadev *rdev, int cq)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(cq >= 0);
    return roce_destroy_cq(ctx, cq);
}

static int rocedev_req_notify_cq(Rdmadev *rdev, int cq, int solicited_only)
{
    return 0;
}

static int rocedev_poll_cq(Rdmadev *rdev, int cq)
{
    return 0;
}

static int rocedev_cq_ctx(Rdmadev *rdev, int cq, void **opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(cq >= 0);
    return roce_cq_ctx(ctx, cq, opaque);
}

static int rocedev_create_qp(Rdmadev *rdev, int pd, uint32_t flags, int srq, int send_cq, int recv_cq, RdmadevQpCap *cap, RdmadevQpType qp_type, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_qp_type _qp_type;
    uint32_t _flags;
    roce_qp_cap _cap = { 0 };

    _qp_type = rocedev_qp_type_from(qp_type);
    if (_qp_type >= ROCE_QPT_MAX) {
        rocedev_warn_report(rocedev, "Create invalid QP type %d", qp_type);
        return -EINVAL;
    }

    _flags = rocedev_qp_flags_from(flags);
    assert(!!_flags == !!flags);

    _cap.max_send_wr = cap->max_send_wr;
    _cap.max_recv_wr = cap->max_recv_wr;
    _cap.max_send_sge = cap->max_send_sge;
    _cap.max_recv_sge = cap->max_recv_sge;
    _cap.max_inline_data = cap->max_inline_data;

    return roce_create_qp(ctx, pd, _qp_type, srq, send_cq, recv_cq, &_cap, _flags, opaque);
}

static int rocedev_destroy_qp(Rdmadev *rdev, int qp)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(qp >= 0);
    return roce_destroy_qp(ctx, qp);
}

static inline void rocedev_fill_ah_attr(roce_ah_attr *ah, RdmadevAhAttr *_ah)
{
    memcpy(ah->gid, _ah->grh.dgid.raw, ROCE_GID_LEN);
    memcpy(ah->mac, _ah->dmac, ROCE_MAC_LEN);
    ah->flow_label = _ah->grh.flow_label;
    ah->sgid_index = _ah->grh.sgid_index;
    ah->hop_limit = _ah->grh.hop_limit;
    ah->traffic_class = _ah->grh.traffic_class;
    ah->port_num = _ah->port_num;
}

static int rocedev_modify_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_qp_attr rattr = { 0 };
    roce_ah_attr *rah;
    RdmadevAhAttr *ah;
    uint32_t mask;

    mask = rocedev_qp_attr_mask_from(attr_mask);
    if (!mask) {
        rocedev_warn_report(rocedev, "Unkonwn QP attributes");
        return -EINVAL;
    }

    if (attr_mask & RDMADEV_QP_STATE) {
        rattr.qp_state = rocedev_qp_state_from(attr->qp_state);
    }

    if (attr_mask & RDMADEV_QP_CUR_STATE) {
        rattr.cur_qp_state = rocedev_qp_state_from(attr->cur_qp_state);
    }

    if (attr_mask & RDMADEV_QP_PATH_MTU) {
        rattr.path_mtu = rocedev_mtu_from(attr->path_mtu);
    }

    if (attr_mask & RDMADEV_QP_ACCESS_FLAGS) {
        rattr.qp_access_flags = rocedev_access_flags_from(attr->qp_access_flags);
    }

    if (attr_mask & RDMADEV_QP_CAP) {
        rattr.cap.max_send_wr = attr->cap.max_send_wr;
        rattr.cap.max_recv_wr = attr->cap.max_recv_wr;
        rattr.cap.max_send_sge = attr->cap.max_send_sge;
        rattr.cap.max_recv_sge = attr->cap.max_recv_sge;
        rattr.cap.max_inline_data = attr->cap.max_inline_data;
    }

    if (mask & ROCE_QP_AV) {
        rah = &rattr.ah_attr;
        ah = &attr->ah_attr;
        rocedev_fill_ah_attr(rah, ah);
    }

    if (attr_mask & RDMADEV_QP_ALT_PATH) {
        rattr.alt_pkey_index = attr->alt_pkey_index;
        rattr.alt_port_num = attr->alt_port_num;
        rattr.alt_timeout = attr->alt_timeout;
        rah = &rattr.alt_ah_attr;
        ah = &attr->alt_ah_attr;
        rocedev_fill_ah_attr(rah, ah);
    }

    rattr.qkey = attr->qkey;
    rattr.rq_psn = attr->rq_psn;
    rattr.sq_psn = attr->sq_psn;
    rattr.pkey_index = attr->pkey_index;
    rattr.dest_qp_num = attr->dest_qp_num;
    rattr.en_sqd_async_notify = attr->en_sqd_async_notify;
    rattr.sq_draining = attr->sq_draining;
    rattr.max_rd_atomic = attr->max_rd_atomic;
    rattr.max_dest_rd_atomic = attr->max_dest_rd_atomic;
    rattr.min_rnr_timer = attr->min_rnr_timer;
    rattr.port_num = attr->port_num;
    rattr.timeout = attr->timeout;
    rattr.retry_cnt = attr->retry_cnt;
    rattr.rnr_retry = attr->rnr_retry;

    return roce_modify_qp(ctx, qp, &rattr, mask);
}

static int rocedev_query_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_qp_attr rattr = { 0 };
    roce_ah_attr *rah = &rattr.ah_attr;
    RdmadevAhAttr *ah = &attr->ah_attr;
    uint32_t mask;
    int ret;

    mask = rocedev_qp_attr_mask_from(attr_mask);
    ret = roce_query_qp(ctx, qp, &rattr, mask);
    if (ret) {
        return ret;
    }

    if (attr_mask & RDMADEV_QP_STATE) {
        attr->qp_state = rocedev_qp_state_to(rattr.qp_state);
    }

    if (attr_mask & RDMADEV_QP_CUR_STATE) {
        attr->cur_qp_state = rocedev_qp_state_to(rattr.cur_qp_state);
    }

    if (attr_mask & RDMADEV_QP_EN_SQD_ASYNC_NOTIFY) {
        attr->en_sqd_async_notify = rattr.en_sqd_async_notify;
    }

    if (attr_mask & RDMADEV_QP_ACCESS_FLAGS) {
        attr->qp_access_flags = rocedev_access_flags_to(rattr.qp_access_flags);
    }

    if (attr_mask & RDMADEV_QP_PKEY_INDEX) {
        attr->pkey_index = rattr.pkey_index;
    }

    if (attr_mask & RDMADEV_QP_PORT) {
        attr->port_num = rattr.port_num;
    }

    if (attr_mask & RDMADEV_QP_AV) {
        memcpy(ah->grh.dgid.raw, rah->gid, ROCE_GID_LEN);
        ah->grh.flow_label = rah->flow_label;
        ah->grh.sgid_index = rah->sgid_index;
        ah->grh.hop_limit = rah->hop_limit;
        ah->grh.traffic_class = rah->traffic_class;
        ah->port_num = rah->port_num;
        memcpy(ah->dmac, rah->mac, ROCE_MAC_LEN);
    }

    if (attr_mask & RDMADEV_QP_PATH_MTU) {
        attr->path_mtu = rocedev_mtu_to(rattr.path_mtu);
    }

    if (attr_mask & RDMADEV_QP_TIMEOUT) {
        attr->timeout = rattr.timeout;
    }

    if (attr_mask & RDMADEV_QP_RETRY_CNT) {
        attr->retry_cnt = rattr.retry_cnt;
    }

    if (attr_mask & RDMADEV_QP_RNR_RETRY) {
        attr->rnr_retry = rattr.rnr_retry;
    }

    if (attr_mask & RDMADEV_QP_RQ_PSN) {
        attr->rq_psn = rattr.rq_psn;
    }

    if (attr_mask & RDMADEV_QP_MAX_QP_RD_ATOMIC) {
        attr->max_rd_atomic = rattr.max_rd_atomic;
    }

    if (attr_mask & RDMADEV_QP_MIN_RNR_TIMER) {
        attr->min_rnr_timer = rattr.min_rnr_timer;
    }

    if (attr_mask & RDMADEV_QP_SQ_PSN) {
        attr->sq_psn = rattr.sq_psn;
    }

    if (attr_mask & RDMADEV_QP_MAX_DEST_RD_ATOMIC) {
        attr->max_dest_rd_atomic = rattr.max_dest_rd_atomic;
    }

    if (attr_mask & RDMADEV_QP_CAP) {
        attr->cap.max_send_wr = rattr.cap.max_send_wr;
        attr->cap.max_recv_wr = rattr.cap.max_recv_wr;
        attr->cap.max_send_sge = rattr.cap.max_send_sge;
        attr->cap.max_recv_sge = rattr.cap.max_recv_sge;
        attr->cap.max_inline_data = rattr.cap.max_inline_data;
    }

    if (attr_mask & RDMADEV_QP_DEST_QPN) {
        attr->dest_qp_num = rattr.dest_qp_num;
    }

    return 0;
}

static int rocedev_qp_ctx(Rdmadev *rdev, int qp, void **opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(qp >= 0);
    return roce_qp_ctx(ctx, qp, opaque);
}

static int rocedev_qp_type(Rdmadev *rdev, int qp)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    int ret;

    assert(qp >= 0);
    ret = roce_get_qp_type(ctx, qp);
    if (ret < 0) {
        return ret;
    }

    return rocedev_qp_type_to(ret);
}

static inline void rocedev_fill_sges(roce_sge *sges, RdmadevSge *_sges, uint32_t num_sge)
{
    roce_sge *sge;
    RdmadevSge *_sge;

    for (uint32_t i = 0; i < num_sge; i++) {
        sge = &sges[i];
        _sge = &_sges[i];
        sge->addr = _sge->addr;
        sge->length = _sge->length;
        sge->lkey = _sge->lkey;
    }
}

static int rocedev_post_recv(Rdmadev *rdev, int qp, RdmadevRecvWr *recv_wr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_recv_wr *_recv_wr;
    int ret;

    ret = roce_alloc_recv_wr(rocedev->ctx, recv_wr->num_sge, &_recv_wr);
    if (ret) {
        return ret;
    }

    rocedev_fill_sges(_recv_wr->sge, recv_wr->sge, recv_wr->num_sge);
    _recv_wr->wr_id = (uint64_t)recv_wr;

    return roce_post_recv(ctx, qp, _recv_wr);
}

static int rocedev_post_send(Rdmadev *rdev, int qp, RdmadevSendWr *send_wr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_send_wr *_send_wr;
    roce_qp_type qp_type;
    int ret;

    ret = roce_alloc_send_wr(rocedev->ctx, send_wr->num_sge, &_send_wr);
    if (ret) {
        return ret;
    }

    switch (send_wr->opcode) {
    case RDMADEV_WR_RDMA_WRITE_WITH_IMM:
        _send_wr->imm_data = send_wr->ex.imm_data;
        /* fall through */

    case RDMADEV_WR_RDMA_WRITE:
        _send_wr->wr.rdma.remote_addr = send_wr->wr.rdma.remote_addr;
        _send_wr->wr.rdma.rkey = send_wr->wr.rdma.rkey;
        break;

    case RDMADEV_WR_SEND_WITH_IMM:
        _send_wr->imm_data = send_wr->ex.imm_data;
        goto send;

    case RDMADEV_WR_SEND_WITH_INV:
        _send_wr->invalidated_rkey = send_wr->ex.invalidate_rkey;
        goto send;

send:
    case RDMADEV_WR_SEND:
        qp_type = roce_get_qp_type(ctx, qp);
        if ((qp_type == ROCE_QPT_UD) ||
            (qp_type == ROCE_QPT_GSI)) {

            _send_wr->wr.ud.remote_qpn = send_wr->wr.ud.remote_qpn;
            _send_wr->wr.ud.remote_qkey = send_wr->wr.ud.remote_qkey;
            _send_wr->wr.ud.ah = send_wr->wr.ud.ah_handle;
        }
        break;
    default:
        rocedev_error_report(rocedev, "Unsupported opcode %s on post send", rdmadev_wr_opcode(_send_wr->opcode));
        goto free_wr;
    }

    _send_wr->wr_id = (uint64_t)send_wr;
    _send_wr->opcode = rocedev_wr_opcode(send_wr->opcode);
    _send_wr->send_flags = rocedev_send_flags_from(send_wr->send_flags);
    rocedev_fill_sges(_send_wr->sge, send_wr->sge, send_wr->num_sge);

    return roce_post_send(ctx, qp, _send_wr);

free_wr:
    roce_free_send_wr(ctx, _send_wr);
    return ret;
}

static int rocedev_create_mr(Rdmadev *rdev, int pd, RdmadevMrTypes mr_type, uint32_t access, uint32_t length, uint64_t iova, uint32_t sg_num, struct iovec *sg, uint32_t *lkey, uint32_t *rkey, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    unsigned int _access = rocedev_access_flags_from(access);
    roce_mr_type _mr_type;
    int mr;

    _mr_type = rocedev_mr_type_from(mr_type);
    if (_mr_type == ROCE_MR_MAX) {
        rocedev_error_report(rocedev, "invalid MR type %d", mr_type);
        return -EINVAL;
    }

    mr = roce_create_mr(ctx, pd, _mr_type, iova, length, _access, sg, sg_num, 0, opaque);
    if (mr < 0) {
        return mr;
    }

    roce_get_mr_key(ctx, mr, lkey, rkey);

    return mr;
}

static int rocedev_destroy_mr(Rdmadev *rdev, int mr)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(mr >= 0);
    return roce_destroy_mr(ctx, mr);
}

static int rocedev_create_ah(Rdmadev *rdev, int pd, RdmadevAhAttr *attr, void *opaque)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;
    roce_ah_attr _attr = { 0 };

    rocedev_fill_ah_attr(&_attr, attr);
    return roce_create_ah(ctx, pd, &_attr, opaque);
}

static int rocedev_destroy_ah(Rdmadev *rdev, int ah)
{
    Rocedev *rocedev = ROCEDEV(rdev);
    roce_ctx ctx = rocedev->ctx;

    assert(ah >= 0);
    return roce_destroy_ah(ctx, ah);
}

static void rocedev_instance_init(Object *obj)
{
    Rocedev *rocedev = ROCEDEV(obj);

    printf("always: %s, %d, rocedev version %d\n", __func__, __LINE__, rocedev->rdev.dev.u.roce.version);
}

static void rocedev_instance_finalize(Object *obj)
{
    Rocedev *rocedev = ROCEDEV(obj);

    printf("always: %s, %d, rocedev version %d\n", __func__, __LINE__, rocedev->rdev.dev.u.roce.version);
}

#define ROCEDEV_PROP_INT(_type, _var, _func)                         \
    static void rocedev_prop_get_##_func(Object *obj, Visitor *v,    \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Rocedev *rocedev = ROCEDEV(obj);                             \
        _type##_t value = _var;                                      \
        visit_type_##_type(v, name, &value, errp);                   \
    }                                                                \
                                                                     \
    static void rocedev_prop_set_##_func(Object *obj, Visitor *v,    \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Rocedev *rocedev = ROCEDEV(obj);                             \
        _type##_t value;                                             \
    if (!visit_type_##_type(v, name, &value, errp)) {                \
        return;                                                      \
    }                                                                \
        _var = value;                                                \
    }

#define ROCEDEV_PROP_STR(_var, _func)                                \
    static char *rocedev_prop_get_##_func(Object *obj, Error **errp) \
    {                                                                \
        Rocedev *rocedev = ROCEDEV(obj);                             \
        return g_strdup(_var);                                       \
    }                                                                \
                                                                     \
    static void rocedev_prop_set_##_func(Object *obj,                \
        const char *value, Error **errp)                             \
    {                                                                \
        Rocedev *rocedev = ROCEDEV(obj);                             \
        if (_var) {                                                  \
            error_setg(errp, #_func " property already set");        \
            return;                                                  \
        }                                                            \
        _var = g_strdup(value);                                      \
    }

static void rocedev_set_RdmaRoceType(Object *obj, Visitor *v, const char *name,
                     void *opaque, Error **errp)
{
    Rocedev *rocedev = ROCEDEV(obj);

    visit_type_RdmaRoceType(v, name, &rocedev->rdev.dev.u.roce.version, errp);
}

static void rocedev_class_init(ObjectClass *oc, void *data)
{
    RdmadevClass *rdc = RDMADEV_CLASS(oc);

    object_class_property_add(oc, "version", "RdmaRoceType", NULL,
                              rocedev_set_RdmaRoceType, NULL, NULL);

    rdc->init_dev = rocedev_init_dev;
    rdc->finalize_dev = rocedev_finalize_dev;

    rdc->init_port = rocedev_init_port;
    rdc->finalize_port = rocedev_finalize_port;
    rdc->query_port = rocedev_query_port;

    rdc->add_gid = rocedev_add_gid;
    rdc->del_gid = rocedev_del_gid;
    rdc->get_gid = rocedev_get_gid;

    rdc->alloc_uc = rocedev_alloc_uc;
    rdc->dealloc_uc = rocedev_dealloc_uc;

    rdc->alloc_pd = rocedev_alloc_pd;
    rdc->dealloc_pd = rocedev_dealloc_pd;

    rdc->create_cq = rocedev_create_cq;
    rdc->destroy_cq = rocedev_destroy_cq;
    rdc->req_notify_cq = rocedev_req_notify_cq;
    rdc->poll_cq = rocedev_poll_cq;
    rdc->cq_ctx = rocedev_cq_ctx;

    rdc->create_qp = rocedev_create_qp;
    rdc->destroy_qp = rocedev_destroy_qp;
    rdc->modify_qp = rocedev_modify_qp;
    rdc->query_qp = rocedev_query_qp;
    rdc->qp_ctx = rocedev_qp_ctx;
    rdc->qp_type = rocedev_qp_type;

    rdc->post_recv = rocedev_post_recv;
    rdc->post_send = rocedev_post_send;

    rdc->create_mr = rocedev_create_mr;
    rdc->destroy_mr = rocedev_destroy_mr;

    rdc->create_ah = rocedev_create_ah;
    rdc->destroy_ah = rocedev_destroy_ah;

#if 0
    rdc->create_srq = rocedev_create_srq;
    rdc->query_srq = rocedev_query_srq;
    rdc->modify_srq = rocedev_modify_srq;
    rdc->destroy_srq = rocedev_destroy_srq;
    rdc->post_srq_recv = rocedev_post_srq_recv;
#endif
}

static const TypeInfo rocedev_type_info = {
    .name = TYPE_ROCEDEV,
    .parent = TYPE_RDMADEV,
    .instance_size = sizeof(Rocedev),
    .instance_init = rocedev_instance_init,
    .instance_finalize = rocedev_instance_finalize,
    .class_init = rocedev_class_init,
};

static void rocedev_register_types(void)
{
    printf("always: %s, %d\n", __func__, __LINE__);
    type_register_static(&rocedev_type_info);
}

type_init(rocedev_register_types);
