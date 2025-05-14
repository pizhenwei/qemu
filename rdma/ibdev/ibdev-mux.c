/*
 * QEMU RDMA Backend Support for host IB device - GID & GSI support
 *
 * Copyright (C) 2018 Oracle
 * Copyright (C) 2018 Red Hat Inc
 * Copyright (c) 2024 Bytedance
 *
 * Authors:
 *     Yuval Shaia <yuval.shaia@oracle.com>
 *     Marcel Apfelbaum <marcel@redhat.com>
 *     zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"

#include <infiniband/verbs.h>

#include "chardev/char-fe.h"
#include "contrib/rdmacm-mux/rdmacm-mux.h"
#include "qapi/error.h"
#include "qapi/qapi-events-rdma.h"
#include "qapi/visitor.h"
#include "rdma/rdma.h"
#include "rdma/resource.h"

#include "../rdmadev.h"
#include "ibdev.h"
#include "trace.h"

static int ibdev_mux_send(Ibdev *ibdev, RdmaCmMuxMsg *req)
{
    RdmaCmMuxMsg resp = { 0 };
    int ret = -EIO;

    trace_ibdev_mux(RDMACM_MUX_MSG_TYPE_REQ, req->hdr.op_code, req->umad_len,
                    RDMACM_MUX_ERR_CODE_OK);

    req->hdr.msg_type = RDMACM_MUX_MSG_TYPE_REQ;
    ret = qemu_chr_fe_write(&ibdev->mad, (const uint8_t *)req, sizeof(*req));
    if (ret != sizeof(*req)) {
        ibdev_error_report("rdmacm mux: Failed to send request %d", ret);
        return -EIO;
    }

    /* Note: this is blocked until rdmacm-mux response */
    ret = qemu_chr_fe_read_all(&ibdev->mad, (uint8_t *)&resp, sizeof(resp));
    if (ret != sizeof(resp)) {
        ibdev_error_report("rdmacm mux: Invalid msg size %d, expecting %d",
                           ret, (int)sizeof(resp));
        return -EIO;
    }

    trace_ibdev_mux(resp.hdr.msg_type, resp.hdr.op_code, resp.umad_len, resp.hdr.err_code);
    if (resp.hdr.msg_type != RDMACM_MUX_MSG_TYPE_RESP) {
        ibdev_error_report("rdmacm mux: Invalid msg type %d", resp.hdr.msg_type);
        return -EIO;
    }

    if (resp.hdr.err_code != RDMACM_MUX_ERR_CODE_OK) {
        ibdev_error_report("rdmacm mux: Operation failed in rdmacm mux: %d",
                           resp.hdr.err_code);
        return -EIO;
    }

    return 0;
}

int ibdev_add_gid(Rdmadev *rdev, RdmaPortAttr *port, RdmaGid *gid)
{
    Ibdev *ibdev = IBDEV(rdev);
    const char *netdev = ibdev->rdev.dev.u.ibdev.netdev;
    RdmaCmMuxMsg req = { 0 };
    RdmadevGid *_gid = (RdmadevGid *)gid->gid;
    int ret;

    trace_ibdev_gid_changed("add", be64_to_cpu(_gid->global.subnet_prefix), be64_to_cpu(_gid->global.interface_id));

    req.hdr.op_code = RDMACM_MUX_OP_CODE_REG;
    memcpy(req.hdr.sgid.raw, gid->gid, sizeof(req.hdr.sgid));

    ret = ibdev_mux_send(ibdev, &req);
    if (ret) {
        return -EIO;
    }

    qapi_event_send_rdma_gid_status_changed(netdev, true,
                                            _gid->global.subnet_prefix,
                                            _gid->global.interface_id);

    return ret;
}

int ibdev_del_gid(Rdmadev *rdev, RdmaPortAttr *port, RdmaGid *gid)
{
    Ibdev *ibdev = IBDEV(rdev);
    const char *netdev = ibdev->rdev.dev.u.ibdev.netdev;
    RdmaCmMuxMsg req = { 0 };
    RdmadevGid *_gid = (RdmadevGid *)gid->gid;
    int ret;

    trace_ibdev_gid_changed("del", be64_to_cpu(_gid->global.subnet_prefix), be64_to_cpu(_gid->global.interface_id));

    req.hdr.op_code = RDMACM_MUX_OP_CODE_UNREG;
    memcpy(req.hdr.sgid.raw, gid->gid, sizeof(req.hdr.sgid));

    ret = ibdev_mux_send(ibdev, &req);
    if (ret) {
        return -EIO;
    }

    qapi_event_send_rdma_gid_status_changed(netdev, false,
                                            _gid->global.subnet_prefix,
                                            _gid->global.interface_id);

    return ret;
}

int ibdev_get_gid(Rdmadev *rdev, RdmaPortAttr *port, uint8_t gid_index, union ibv_gid *sgid)
{
    Ibdev *ibdev = IBDEV(rdev);
    char gid_str[INET6_ADDRSTRLEN] = {};
    union ibv_gid igid;
    RdmaGid *gid;
    int ret;
    int i = 0;

    gid = rdmadev_get_gid(port, gid_index);
    if (!gid) {
        ibdev_error_report("Invalid GID %d", gid_index);
        return -EINVAL;
    }

    do {
        ret = ibv_query_gid(ibdev->ibv_ctx, ibdev->rdev.dev.u.ibdev.ibport, i,
                            &igid);
        i++;
    } while (!ret && (memcmp(igid.raw, gid->gid, sizeof(igid.raw))));

    if (ret) {
        /* this should not happen, does anyone outside removes this GID? */
        return -EIO;
    }

    if (sgid) {
        memcpy(sgid->raw, igid.raw, sizeof(igid.raw));
    }

    inet_ntop(AF_INET6, gid->gid, gid_str, sizeof(gid_str));
    trace_ibdev_get_gid(gid_str, gid_index, i - 1);

    return i - 1;
}

static void ibdev_gsi_comp(Ibdev *ibdev, void *wr, bool is_send, RdmadevWcStatus status)
{
    Rdmadev *rdev = &ibdev->rdev;
    RdmadevCq *cq;
    RdmadevWc wc = { 0 };
    uint32_t num_sge;
    RdmadevSge *sge;

    if (is_send) {
        cq = &ibdev->gsi_send_cq->rcq;
        RdmadevSendWr *send_wr = (RdmadevSendWr *)wr;
        wc.wr_id = send_wr->wr_id;
        wc.opcode = RDMADEV_WC_SEND;
        wc.wc_flags = 0;
        sge = send_wr->sge;
        num_sge = send_wr->num_sge;
    } else {
        cq = &ibdev->gsi_recv_cq->rcq;
        RdmadevRecvWr *recv_wr = (RdmadevRecvWr *)wr;
        wc.wr_id = recv_wr->wr_id;
        wc.opcode = RDMADEV_WC_RECV;
        wc.wc_flags = RDMADEV_WC_GRH | RDMADEV_WC_WITH_NETWORK_HDR_TYPE;
        wc.network_hdr_type = RDMADEV_NETWORK_IPV4;
        sge = recv_wr->sge;
        num_sge = recv_wr->num_sge;
    }

    for (uint32_t i = 0; i < num_sge; i++) {
        wc.byte_len += sge[i].length;
    }

    wc.qp_handle = 1;
    wc.remote_qp_handle = 1;
    wc.status = status;
    wc.wr = wr;

    rdev->cq_comp(cq, &wc, rdev->hwdev);
}

int ibdev_post_send_gsi(Rdmadev *rdev, RdmadevQp *qp, RdmadevSendWr *send_wr)
{
    Ibdev *ibdev = IBDEV(rdev);
    RdmaCmMuxMsg req = { 0 };
    IbdevAh *ah;
    RdmadevWcStatus status;
    int ret;

    ah = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_AH, send_wr->wr.ud.ah_handle);
    if (!ah) {
        ibdev_error_report("Failed to get AH for GSI");
        return -EINVAL;
    }

    for (int i = 0; i < send_wr->num_sge; i++) {
        RdmadevSge *sge = &send_wr->sge[i];
        RdmadevMr *mr = rdmadev_mr_by_lkey(rdev, qp->pd_handle, sge->lkey);
        void *buf;

        if (!mr) {
            ibdev_error_report("Invalid lkey 0x%x of PD %d for GSI", sge->lkey, qp->pd_handle);
            return -EINVAL;
        }

        if (mr->mr_type != RDMADEV_MR_DMA) {
            ibdev_error_report("GSI supports DMA MR only");
            return -EACCES;
        }

        if (req.umad_len + sge->length > sizeof(req.umad.mad)) {
            ibdev_error_report("MAD message size too large");
            return -ENOMEM;
        }

        buf = rdev->dma_map(rdev->hwdev, sge->addr, sge->length);
        if (!buf) {
            ibdev_error_report("DMA MR map failed for GSI");
            return -EACCES;
        }

        memcpy(&req.umad.mad[req.umad_len], buf, sge->length);
        req.umad_len += sge->length;

        rdev->dma_unmap(rdev->hwdev, buf, sge->length);
    }

    req.hdr.op_code = RDMACM_MUX_OP_CODE_MAD;
    memcpy(req.hdr.sgid.raw, ah->sgid.raw, sizeof(req.hdr.sgid));

    req.umad.hdr.addr.qpn = htobe32(1);
    req.umad.hdr.addr.grh_present = 1;
    req.umad.hdr.addr.gid_index = ah->ibah_attr.grh.sgid_index;
    req.umad.hdr.addr.hop_limit = ah->ibah_attr.grh.hop_limit;
    memcpy(req.umad.hdr.addr.gid, ah->sgid.raw, sizeof(req.umad.hdr.addr.gid));

    ret = ibdev_mux_send(ibdev, &req);
    status = ret ? RDMADEV_WC_GENERAL_ERR : RDMADEV_WC_SUCCESS;
    ibdev_gsi_comp(ibdev, send_wr, true, status);

    return ret;
}

int ibdev_mux_can_receive(void *opaque)
{
    return 1;
}

void ibdev_mux_read(void *opaque, const uint8_t *buf, int size)
{
    Ibdev *ibdev = opaque;
    Rdmadev *rdev = &ibdev->rdev;
    RdmaCmMuxMsg *msg = &ibdev->in_msg;
    IbdevGsiRecvWr *gsi_recv_wr;
    RdmadevRecvWr *recv_wr;
    int to_copy = sizeof(RdmaCmMuxMsg) - ibdev->in_msg_size;
    uint32_t mad_hdr_size = sizeof(struct ibv_grh);
    RdmadevSge *sge;
    RdmadevQp *qp;
    RdmadevMr *mr;
    struct ibv_grh *igrh;
    uint8_t *mad;

    /* copy message from rdmacm-mux, handle incoming MAD once the msg is fully received */
    to_copy = MIN(to_copy, size);
    memcpy((uint8_t *)msg + ibdev->in_msg_size, buf, to_copy);
    ibdev->in_msg_size += to_copy;
    if (ibdev->in_msg_size < sizeof(RdmaCmMuxMsg)) {
        return;
    }

    ibdev->in_msg_size = 0;
    if (msg->hdr.msg_type != RDMACM_MUX_MSG_TYPE_REQ &&
        msg->hdr.op_code != RDMACM_MUX_OP_CODE_MAD) {
            ibdev_error_report("Error: Not a MAD request, skipping");
            return;
    }

    gsi_recv_wr = QTAILQ_FIRST(&ibdev->gsi_recv_wrs);
    if (!gsi_recv_wr) {
        ibdev_error_report("Ignore GSI request");
        return;
    }

    recv_wr = gsi_recv_wr->wr;
    if (recv_wr->num_sge != 1) {
        ibdev_error_report("A single SGE is support by GSI");
        return;
    }

    sge = &recv_wr->sge[0];
    if (sge->length < mad_hdr_size + msg->umad_len) {
        ibdev_error_report("GSI recv buffer too small");
        return;
    }

    qp = rdmadev_get_qp(rdev, RDMADEV_QPT_GSI);
    if (!qp) {
        ibdev_error_report("GSI is not enabled");
        return;
    }

    mr = rdmadev_mr_by_lkey(rdev, qp->pd_handle, sge->lkey);
    if (!mr) {
        ibdev_error_report("Invalid lkey 0x%x of PD %d for GSI", sge->lkey, qp->pd_handle);
        return;
    }


    if (mr->mr_type != RDMADEV_MR_DMA) {
        ibdev_error_report("GSI supports DMA MR only");
        return;
    }

    mad = rdev->dma_map(rdev->hwdev, sge->addr, sge->length);
    if (!mad) {
        ibdev_error_report("DMA MR map failed for GSI");
        return;
    }

    igrh = (struct ibv_grh *)mad;
    igrh->paylen = htons(msg->umad_len);
    memcpy(igrh->sgid.raw, msg->hdr.sgid.raw, sizeof(igrh->sgid.raw));
    memcpy(igrh->dgid.raw, msg->umad.hdr.addr.gid, sizeof(igrh->dgid.raw));
    memcpy(mad + mad_hdr_size, msg->umad.mad, msg->umad_len);
    rdev->dma_unmap(rdev->hwdev, mad, sge->length);
    ibdev_gsi_comp(ibdev, recv_wr, false, RDMADEV_WC_SUCCESS);

    QTAILQ_REMOVE(&ibdev->gsi_recv_wrs, gsi_recv_wr, next);
    g_free(gsi_recv_wr);
}
