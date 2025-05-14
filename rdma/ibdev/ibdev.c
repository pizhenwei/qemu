/*
 * QEMU RDMA Backend Support for host IB device.
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
#include "exec/cpu-common.h"
#include "qemu/iov.h"
#include "qemu/memalign.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "rdma/rdma.h"
#include "rdma/resource.h"
#include "ibdev.h"
#include "../rdmadev.h"
#include "trace.h"

#include "ibdev-types.h"

#define VERIFY_DEV_ATTR(x, y, f)                               \
    if (x && (x > y)) {                                        \
        ibdev_error_report("Failed to set dev attr %s"         \
           " to %" PRId64 ", exceeds %" PRId64, f,             \
            (uint64_t)x, (uint64_t)y);                         \
        goto error;                                            \
    }

static int ibdev_init_dev_attr(Ibdev *ibdev)
{
    RdmaDevAttr *dev_attr = &ibdev->rdev.dev_attr;
    struct ibv_device_attr ibv_attr;
    int ret;

    ret = ibv_query_device(ibdev->ibv_ctx, &ibv_attr);
    if (ret) {
        ibdev_error_report("ibv_query_device failed: %m");
        return ret;
    }

    VERIFY_DEV_ATTR(dev_attr->max_mr_size, ibv_attr.max_mr_size, "max_mr_size");
    VERIFY_DEV_ATTR(dev_attr->page_size_cap, ibv_attr.page_size_cap, "page_size_cap");
    VERIFY_DEV_ATTR(dev_attr->max_qp, ibv_attr.max_qp, "max_qp");
    VERIFY_DEV_ATTR(dev_attr->max_qp_wr, ibv_attr.max_qp_wr, "max_qp_wr");
    VERIFY_DEV_ATTR(dev_attr->max_sge, ibv_attr.max_sge, "max_sge");
    VERIFY_DEV_ATTR(dev_attr->max_sge_rd, ibv_attr.max_sge_rd, "max_sge_rd");
    VERIFY_DEV_ATTR(dev_attr->max_cq, ibv_attr.max_cq, "max_cq");
    VERIFY_DEV_ATTR(dev_attr->max_cqe, ibv_attr.max_cqe, "max_cqe");
    VERIFY_DEV_ATTR(dev_attr->max_mr, ibv_attr.max_mr, "max_mr");
    VERIFY_DEV_ATTR(dev_attr->max_pd, ibv_attr.max_pd, "max_pd");
    VERIFY_DEV_ATTR(dev_attr->max_qp_rd_atom, ibv_attr.max_qp_rd_atom, "max_qp_rd_atom");
    VERIFY_DEV_ATTR(dev_attr->max_ee_rd_atom, ibv_attr.max_ee_rd_atom, "max_ee_rd_atom");
    VERIFY_DEV_ATTR(dev_attr->max_res_rd_atom, ibv_attr.max_res_rd_atom, "max_res_rd_atom");
    VERIFY_DEV_ATTR(dev_attr->max_qp_init_rd_atom, ibv_attr.max_qp_init_rd_atom, "max_qp_init_rd_atom");
    VERIFY_DEV_ATTR(dev_attr->max_ee_init_rd_atom, ibv_attr.max_ee_init_rd_atom, "max_ee_init_rd_atom");
    VERIFY_DEV_ATTR(dev_attr->max_ee, ibv_attr.max_ee, "max_ee");
    VERIFY_DEV_ATTR(dev_attr->max_rdd, ibv_attr.max_rdd, "max_rdd");
    VERIFY_DEV_ATTR(dev_attr->max_mw, ibv_attr.max_mw, "max_mw");
    VERIFY_DEV_ATTR(dev_attr->max_raw_ipv6_qp, ibv_attr.max_raw_ipv6_qp, "max_raw_ipv6_qp");
    VERIFY_DEV_ATTR(dev_attr->max_raw_ethy_qp, ibv_attr.max_raw_ethy_qp, "max_raw_ethy_qp");
    VERIFY_DEV_ATTR(dev_attr->max_mcast_grp, ibv_attr.max_mcast_grp, "max_mcast_grp");
    VERIFY_DEV_ATTR(dev_attr->max_mcast_qp_attach, ibv_attr.max_mcast_qp_attach, "max_mcast_qp_attach");
    VERIFY_DEV_ATTR(dev_attr->max_total_mcast_qp_attach, ibv_attr.max_total_mcast_qp_attach, "max_total_mcast_qp_attach");
    VERIFY_DEV_ATTR(dev_attr->max_ah, ibv_attr.max_ah, "max_ah");
    /* FMR is supported by QEMU rdma framework */
    VERIFY_DEV_ATTR(dev_attr->max_fmr, ibv_attr.max_fmr, "max_fmr");
    VERIFY_DEV_ATTR(dev_attr->max_map_per_fmr, ibv_attr.max_map_per_fmr, "max_map_per_fmr");
    VERIFY_DEV_ATTR(dev_attr->max_srq, ibv_attr.max_srq, "max_srq");
    VERIFY_DEV_ATTR(dev_attr->max_srq_wr, ibv_attr.max_srq_wr, "max_srq_wr");
    VERIFY_DEV_ATTR(dev_attr->max_srq_sge, ibv_attr.max_srq_sge, "max_srq_sge");
    dev_attr->max_pkeys = ibv_attr.max_pkeys;
    VERIFY_DEV_ATTR(dev_attr->local_ca_ack_delay, ibv_attr.local_ca_ack_delay, "local_ca_ack_delay");
    dev_attr->device_cap_flags = ibdev_device_cap(ibv_attr.device_cap_flags);
    dev_attr->atomic_cap = ibdev_atomic_cap(ibv_attr.atomic_cap);

    return 0;

error:
    memset(dev_attr, 0x00, sizeof(*dev_attr));
    return -EINVAL;
}

static void ibdev_cq_comp(Ibdev *ibdev, struct ibv_cq *ibcq, struct ibv_wc *iwc)
{
    Rdmadev *rdev = &ibdev->rdev;
    RdmadevCq *cq = ibcq->cq_context;
    RdmadevWc wc = { 0 };

    if (iwc->opcode == IBV_WC_RECV || iwc->opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
        RdmadevRecvWr *recv_wr = (RdmadevRecvWr *)iwc->wr_id;
        wc.wr_id = recv_wr->wr_id;
    } else {
        RdmadevSendWr *send_wr = (RdmadevSendWr *)iwc->wr_id;
        wc.wr_id = send_wr->wr_id;
    }
    wc.qp_handle = iwc->qp_num;
    wc.remote_qp_handle = iwc->src_qp;
    wc.byte_len = iwc->byte_len;
    wc.wc_flags = ibdev_wc_flags_to(iwc->wc_flags);
    wc.ex.imm_data = iwc->imm_data;
    wc.opcode = ibdev_wc_opcode_to(iwc->opcode);
    wc.status = ibdev_wc_status_to(iwc->status);
    wc.pkey_index = iwc->pkey_index;
    wc.slid = iwc->slid;
    wc.sl = iwc->sl;
    wc.dlid_path_bits = iwc->dlid_path_bits;
    wc.wr = (void *)iwc->wr_id;

    rdev->cq_comp(cq, &wc, rdev->hwdev);
}

static int ibdev_poll_ibcq(Ibdev *ibdev, struct ibv_cq *ibcq)
{
#define IBDEV_WC_BATCH 16
    struct ibv_wc wcs[IBDEV_WC_BATCH], *wc;
    int nevents = 0, total_events = 0;

    do {
        nevents = ibv_poll_cq(ibcq, ARRAY_SIZE(wcs), wcs);
        if (nevents < 0) {
            ibdev_error_report("ibv_poll_cq failed: %m");
            return -errno;
        }

        for (int i = 0; i < nevents; i++) {
            wc = &wcs[i];
            ibdev_cq_comp(ibdev, ibcq, wc);
        }

        total_events += nevents;
    } while(nevents == ARRAY_SIZE(wcs));

    return total_events;
}

static void ibdev_async_event_handler(void *arg)
{
    Ibdev *ibdev = arg;
    struct ibv_async_event event;

    while (1) {
        if (ibv_get_async_event(ibdev->ibv_ctx, &event)) {
            break;
        }

        ibv_ack_async_event(&event);
    }
}

static void ibdev_comp_channel_handler(void *arg)
{
    Ibdev *ibdev = arg;
    struct ibv_cq *ev_cq;
    void *ev_ctx;
    int ret;

    while (true) {
        ret = ibv_get_cq_event(ibdev->ibv_chan, &ev_cq, &ev_ctx);
        if (ret) {
            if (errno != EAGAIN) {
                ibdev_error_report("ibv_get_cq_event failed: %m");
            }
            break;
        }

        ibv_ack_cq_events(ev_cq, 1);
        ibdev_poll_ibcq(ibdev, ev_cq);
    }
}

static int ibdev_init_res(Rdmadev *rdev)
{
    RdmaDevAttr *dev_attr = &rdev->dev_attr;
    RdmadevResource *res;

    rdev->res = g_new0(RdmadevResource, RDMADEV_RESOURCE_MAX);

    /* no limitation of UC/PD for ibdev driver, keep same as max-qp */
    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_UC;
    rdmadev_resource_init(res, dev_attr->max_qp, false);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_PD;
    rdmadev_resource_init(res, dev_attr->max_qp, false);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_CQ;
    rdmadev_resource_init(res, dev_attr->max_cq, false);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_MR;
    rdmadev_resource_init(res, dev_attr->max_mr, true);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_QP;
    rdmadev_resource_init(res, dev_attr->max_qp, true);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_SRQ;
    rdmadev_resource_init(res, dev_attr->max_srq, false);

    res = (RdmadevResource *)rdev->res + RDMADEV_RESOURCE_AH;
    rdmadev_resource_init(res, dev_attr->max_ah, false);

    return 0;
}

static void ibdev_free_res(Rdmadev *rdev)
{
    RdmadevResource *res;

    for (uint32_t i = 0; i < RDMADEV_RESOURCE_MAX; i++) {
        res = (RdmadevResource *)rdev->res + i;
        rdmadev_resource_free(res);
    }

    g_free(rdev->res);
}

static int ibdev_init_ibdev(Ibdev *ibdev)
{
    const char *ibdev_name = ibdev->rdev.dev.u.ibdev.ibdev;
    struct ibv_device **dev_list;
    int num_ibv_devices, i;
    int flags;
    int ret = 0;

    /* find the specific host ibdevice */
    dev_list = ibv_get_device_list(&num_ibv_devices);
    if (!dev_list || !num_ibv_devices) {
        ibdev_error_report("ibv_get_device_list failed: %m");
        return -EIO;
    }

    for (i = 0; dev_list[i]; ++i) {
        if (!strcmp(ibv_get_device_name(dev_list[i]), ibdev_name)) {
            break;
        }
    }

    ibdev->ibv_dev = dev_list[i];
    if (!ibdev->ibv_dev) {
        ibdev_error_report("Failed to find device %s", ibdev_name);
        ret = -EIO;
        goto out_free_dev_list;
    }

    ibdev_info_report("uverb device %s", ibdev_name);

    /* open device, use a single ibv_ctx */
    ibdev->ibv_ctx = ibv_open_device(ibdev->ibv_dev);
    if (!ibdev->ibv_ctx) {
        ibdev_error_report("ibv_open_device %s failed: %m", ibdev_name);
        ret = -EIO;
        goto out_free_dev_list;
    }

    /* setup async-fd handler */
    flags = fcntl(ibdev->ibv_ctx->async_fd, F_GETFL);
    fcntl(ibdev->ibv_ctx->async_fd, F_SETFL, flags | O_NONBLOCK);
    aio_set_fd_handler(qemu_get_aio_context(), ibdev->ibv_ctx->async_fd, ibdev_async_event_handler, NULL, NULL, NULL, ibdev);

    /* initialize device attributes */
    if (ibdev_init_dev_attr(ibdev)) {
        goto out_close_device;
    }

    /* initialize resources */
    ibdev_init_res(&ibdev->rdev);

    /* create a single comp channel, setup handler */
    ibdev->ibv_chan = ibv_create_comp_channel(ibdev->ibv_ctx);
    if (!ibdev->ibv_chan) {
        ibdev_error_report("ibv_create_comp_channel %s failed: %m", ibdev_name);
        ret = -EIO;
        goto out_free_res;
    }

    flags = fcntl(ibdev->ibv_chan->fd, F_GETFL);
    fcntl(ibdev->ibv_chan->fd, F_SETFL, flags | O_NONBLOCK);
    aio_set_fd_handler(qemu_get_aio_context(), ibdev->ibv_chan->fd, ibdev_comp_channel_handler, NULL, NULL, NULL, ibdev);

    goto out_free_dev_list;

out_free_res:
    ibdev_free_res(&ibdev->rdev);

out_close_device:
    aio_set_fd_handler(qemu_get_aio_context(), ibdev->ibv_ctx->async_fd, NULL, NULL, NULL, NULL, NULL);
    ibv_close_device(ibdev->ibv_ctx);

out_free_dev_list:
    ibv_free_device_list(dev_list);

    return ret;
}

static int ibdev_init_mad(Ibdev *ibdev)
{
    char *chr_name = ibdev->rdev.dev.u.ibdev.mad_chardev;
    Chardev *chr;
    Error *err = NULL;

    if (!chr_name) {
        ibdev_error_report("Missing mad-chardev parameter");
        return -EINVAL;
    }

    chr = qemu_chr_find(chr_name);
    if (!chr) {
        ibdev_error_report("Failed to find chardev for MAD %s", chr_name);
        return -ENOENT;
    }

    if (!qemu_chr_fe_init(&ibdev->mad, chr, &err)) {
        error_report_err(err);
        return -ENOENT;
    }

    qemu_chr_fe_set_handlers(&ibdev->mad, ibdev_mux_can_receive, ibdev_mux_read, NULL, NULL, ibdev, NULL, true);

    return 0;
}

static int ibdev_init_dev(Rdmadev *rdev)
{
    Ibdev *ibdev = IBDEV(rdev);
    RdmaDevAttr *dev_attr = &rdev->dev_attr;
    int ret;

    if (dev_attr->phys_port_cnt > IBDEV_MAX_PORT) {
        ibdev_error_report("support %d ports only", IBDEV_MAX_PORT);
        return -ENOMEM;
    }

    ret = ibdev_init_ibdev(ibdev);
    if (ret) {
        return ret;
    }

    ret = ibdev_init_mad(ibdev);
    if (ret) {
        return ret;
    }

    QTAILQ_INIT(&ibdev->gsi_recv_wrs);
    return 0;
}

static void ibdev_finalize_dev(Rdmadev *rdev)
{
}

#define VERIFY_PORT_ATTR(x, y, z, f)                               \
    do {                                                           \
        if (y && (y > z)) {                                        \
            ibdev_error_report("Failed to set port attr %s"        \
               " to %" PRId64 ", exceeds %" PRId64, f,             \
                (uint64_t)y, (uint64_t)z);                         \
            goto error;                                            \
        }                                                          \
        x = y;                                                     \
    } while (false);


static int ibdev_init_port_attr(Ibdev *ibdev, RdmaPortAttr *port)
{
    struct ibv_port_attr ibv_attr;
    RdmaPortAttr *_port = &ibdev->rdev.port_attr;
    const char *ibdev_name = ibdev->rdev.dev.u.ibdev.ibdev;
    uint8_t ibport = ibdev->rdev.dev.u.ibdev.ibport;
    int ret;

    ret = ibv_query_port(ibdev->ibv_ctx, ibport, &ibv_attr);
    if (ret) {
        ibdev_error_report("Failed to query port %d of device %s: %m", ibport, ibdev_name);
        return ret;
    }

    if (ibv_attr.state != IBV_PORT_ACTIVE) {
        ibdev_error_report("Inactive port %d of device %s", ibport, ibdev_name);
        return -ENXIO;
    }

    port->max_mtu = ibdev_mtu_to(ibv_attr.max_mtu);
    port->active_mtu = ibdev_mtu_to(ibv_attr.active_mtu);

    /* XXX: active_speed_ex is supported for 200Gbps since rdma-core v49.
      speed = ibv_attr.active_speed_ex ? ibv_attr.active_speed_ex :
                                         ibv_attr.active_speed;
    */
    port->active_speed = ibdev_speed_to(ibv_attr.active_speed);
    port->link_layer = ibdev_link_layer_to(ibv_attr.link_layer);
    port->gid_tbl_len = ibv_attr.gid_tbl_len;
    port->port_cap_flags = ibdev_port_cap_to(ibv_attr.port_cap_flags);
    VERIFY_PORT_ATTR(port->max_msg_sz, _port->max_msg_sz, ibv_attr.max_msg_sz, "max_msg_sz");
    VERIFY_PORT_ATTR(port->bad_pkey_cntr, _port->bad_pkey_cntr, ibv_attr.bad_pkey_cntr, "bad_pkey_cntr");
    VERIFY_PORT_ATTR(port->qkey_viol_cntr, _port->qkey_viol_cntr, ibv_attr.qkey_viol_cntr, "qkey_viol_cntr");
    VERIFY_PORT_ATTR(port->pkey_tbl_len, _port->pkey_tbl_len, ibv_attr.pkey_tbl_len, "pkey_tbl_len");

    return 0;

error:
    memset(port, 0x00, sizeof(*port));
    return -EINVAL;
}

static int ibdev_init_port(Rdmadev *rdev, RdmaPortAttr *port)
{
    Ibdev *ibdev = IBDEV(rdev);
    int ret;

    if (port->index != 1) {
        ibdev_error_report("Single port is supported");
        return -ENXIO;
    }

    ret = ibdev_init_port_attr(ibdev, port);
    if (ret) {
        return ret;
    }

    return 0;
}

static void ibdev_finalize_port(Rdmadev *rdev, RdmaPortAttr *port)
{
}

static int ibdev_alloc_uc(Rdmadev *rdev, uint32_t *uc_handle)
{
    IbdevUc *uc = g_new0(IbdevUc, 1);
    int ret;

    ret = __rdmadev_resource_alloc(rdev->res, RDMADEV_RESOURCE_UC, uc_handle, uc);
    if (ret) {
        g_free(uc);
    }

    return ret;
}

static int ibdev_dealloc_uc(Rdmadev *rdev, uint32_t uc_handle)
{
    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_UC, uc_handle);
}

static int ibdev_alloc_pd(Rdmadev *rdev, uint32_t uc_handle, uint32_t *pd_handle)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevPd *pd = g_new0(IbdevPd, 1);
    int ret = -EIO;

    pd->ibpd = ibv_alloc_pd(ibdev->ibv_ctx);
    if (!pd->ibpd) {
        ibdev_error_report("ibv_alloc_pd failed: %m");
        goto free_pd;
    }

    ret = __rdmadev_resource_alloc(rdev->res, RDMADEV_RESOURCE_PD, pd_handle, pd);
    if (ret) {
        goto destroy_pd;
    }

    return 0;

destroy_pd:
    ibv_dealloc_pd(pd->ibpd);

free_pd:
    g_free(pd);
    return ret;
}

static int ibdev_dealloc_pd(Rdmadev *rdev, uint32_t pd_handle)
{
    IbdevPd *pd = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);

    if (!pd) {
        ibdev_warn_report("Dealloc invalid PD %d", pd_handle);
        return -EINVAL;
    }

    assert(pd->ibpd);
    ibv_dealloc_pd(pd->ibpd);

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);
}

static int ibdev_create_cq(Rdmadev *rdev, uint32_t cqe, uint32_t comp_vector, uint32_t *cq_handle)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevCq *cq = g_new0(IbdevCq, 1);
    int ret = -EIO;

    cq->ibcq = ibv_create_cq(ibdev->ibv_ctx, cqe, cq, ibdev->ibv_chan, comp_vector);
    if (!cq->ibcq) {
        ibdev_error_report("ibv_create_cq failed: %m");
        goto free_cq;
    }

    if (ibv_req_notify_cq(cq->ibcq, 0)) {
        ibdev_warn_report("ibv_req_notify_cq failed on creating: %m");
        goto destroy_cq;
    }

    ret = __rdmadev_resource_alloc(rdev->res, RDMADEV_RESOURCE_CQ, cq_handle, cq);
    if (ret) {
        goto destroy_cq;
    }

    return 0;

destroy_cq:
    ibv_destroy_cq(cq->ibcq);

free_cq:
    g_free(cq);

    return ret;
}

static int ibdev_destroy_cq(Rdmadev *rdev, uint32_t cq_handle)
{
    IbdevCq *cq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_CQ, cq_handle);

    if (!cq) {
        ibdev_warn_report("Destroy invalid CQ %d", cq_handle);
        return -EINVAL;
    }

    assert(cq->ibcq);
    ibv_destroy_cq(cq->ibcq);

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_CQ, cq_handle);
}

static int ibdev_req_notify_cq(Rdmadev *rdev, uint32_t cq_handle, int solicited_only)
{
    IbdevCq *cq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_CQ, cq_handle);

    if (!cq) {
        ibdev_warn_report("Req notify on invalid CQ %d", cq_handle);
        return -EINVAL;
    }

    assert(cq->ibcq);
    return ibv_req_notify_cq(cq->ibcq, solicited_only);
}

static int ibdev_poll_cq(Rdmadev *rdev, uint32_t cq_handle)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevCq *cq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_CQ, cq_handle);

    if (!cq) {
        ibdev_warn_report("Poll invalid CQ %d", cq_handle);
        return -EINVAL;
    }

    assert(cq->ibcq);
    ibdev_poll_ibcq(ibdev, cq->ibcq);

    return 0;
}

static int ibdev_create_qp(Rdmadev *rdev, uint32_t pd_handle, uint32_t flags, uint32_t srq_handle, uint32_t send_cq_handle, uint32_t recv_cq_handle, uint32_t max_send_wr, uint32_t max_recv_wr, uint32_t max_send_sge, uint32_t max_recv_sge, uint32_t max_inline_data, RdmadevQpType qp_type, uint32_t *qp_handle)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevQp *qp;
    IbdevPd *pd;
    IbdevCq *scq, *rcq;
    IbdevSrq *srq;
    struct ibv_qp_init_attr attr = {};
    int ret = -EIO;
    uint32_t __qp_handle = 0;

    switch (qp_type) {
    case RDMADEV_QPT_GSI:
        __qp_handle = RDMADEV_QPT_GSI;
        break;

    case RDMADEV_QPT_RC:
        attr.qp_type = IBV_QPT_RC;
        break;

    case RDMADEV_QPT_UD:
        attr.qp_type = IBV_QPT_UD;
        break;

    case RDMADEV_QPT_UC:
        attr.qp_type = IBV_QPT_UC;
        break;

    case RDMADEV_QPT_SMI:
    default:
        ibdev_error_report("Unsupported QP type %d", qp_type);
        return -EINVAL;
    }

    pd = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);
    if (!pd) {
        ibdev_error_report("Invalid pd-handle %d", pd_handle);
        return -EINVAL;
    }

    scq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_CQ, send_cq_handle);
    if (!scq) {
        ibdev_error_report("Invalid send cq-handle %d", send_cq_handle);
        return -EINVAL;
    }

    rcq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_CQ, recv_cq_handle);
    if (!rcq) {
        ibdev_error_report("Invalid recv cq-handle %d", recv_cq_handle);
        return -EINVAL;
    }

    assert(pd->ibpd);
    assert(scq->ibcq);
    assert(rcq->ibcq);

    if (flags & RDMADEV_QP_SRQ) {
    }

    qp = g_new0(IbdevQp, 1);
    if (qp_type == RDMADEV_QPT_GSI) {
        ibdev->gsi_send_cq = scq;
        ibdev->gsi_recv_cq = rcq;
    } else {
        attr.qp_context = qp;
        attr.send_cq = scq->ibcq;
        attr.recv_cq = rcq->ibcq;
        if (flags & RDMADEV_QP_SRQ) {
            srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
            if (!srq) {
                ibdev_error_report("Invalid srq-handle %d", srq_handle);
                goto free_qp;
            }
            assert(srq->ibsrq);
            attr.srq = srq->ibsrq;
        }
        if (flags & RDMADEV_QP_SIG_ALL) {
            attr.sq_sig_all = 1;
        }
        attr.cap.max_send_wr = max_send_wr;
        attr.cap.max_recv_wr = max_recv_wr;
        attr.cap.max_send_sge = max_send_sge;
        attr.cap.max_recv_sge = max_recv_sge;
        attr.cap.max_inline_data = max_inline_data;
        qp->ibqp = ibv_create_qp(pd->ibpd, &attr);
        if (!qp->ibqp) {
            ibdev_error_report("ibv_create_qp failed: %m");
            goto free_qp;
        }

       __qp_handle = qp->ibqp->qp_num;
    }

    ret = __rdmadev_resource_alloc_at(rdev->res, RDMADEV_RESOURCE_QP, __qp_handle, qp);
    if (ret) {
        goto free_qp;
    }

    *qp_handle = __qp_handle;
    return 0;

free_qp:
    if (qp->ibqp) {
        ibv_destroy_qp(qp->ibqp);
    }
    g_free(qp);

    return ret;
}

static int ibdev_destroy_qp(Rdmadev *rdev, uint32_t qp_handle)
{
    IbdevQp *qp = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_QP, qp_handle);

    if (!qp) {
        ibdev_warn_report("Destroy invalid QP %d", qp_handle);
        return -EINVAL;
    }

    if (qp->rqp.qp_type != RDMADEV_QPT_GSI) {
        assert(qp->ibqp);
        ibv_destroy_qp(qp->ibqp);
    }

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_QP, qp_handle);
}

static int ibdev_ah_attr(Rdmadev *rdev, RdmadevAhAttr *ah, struct ibv_ah_attr *iah, union ibv_gid *sgid)
{
    RdmadevGlobalRoute *grh = &ah->grh;
    struct ibv_global_route *igrh = &iah->grh;
    RdmaPortAttr *port;
    uint8_t port_num = ah->port_num;
    int sgid_index;

    port = rdmadev_query_port(rdev, port_num);
    if (!port) {
        return -EIO;
    }

    sgid_index = ibdev_get_gid(rdev, port, grh->sgid_index, sgid);
    if (sgid_index < 0) {
        return -EINVAL;
    }

    memcpy(&igrh->dgid.raw, &grh->dgid.raw, sizeof(igrh->dgid.raw));
    igrh->sgid_index = sgid_index;
    igrh->hop_limit = grh->hop_limit;
    igrh->traffic_class = grh->traffic_class;
    igrh->flow_label = grh->flow_label;
        ibdev_error_report("ibdev_ah_attr sgid_index %d, dgid %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", sgid_index, igrh->dgid.raw[0], igrh->dgid.raw[1], igrh->dgid.raw[2], igrh->dgid.raw[3], igrh->dgid.raw[4],igrh->dgid.raw[5],igrh->dgid.raw[6],igrh->dgid.raw[7],igrh->dgid.raw[8],igrh->dgid.raw[9],igrh->dgid.raw[10],igrh->dgid.raw[11],igrh->dgid.raw[12],igrh->dgid.raw[13],igrh->dgid.raw[14],igrh->dgid.raw[15]);

    iah->dlid = ah->dlid;
    iah->sl = ah->sl;
    iah->src_path_bits = ah->src_path_bits;
    iah->static_rate = ah->static_rate;
    iah->is_global = 1;
    iah->port_num = rdev->dev.u.ibdev.ibport;

    return 0;
}

static int ibdev_modify_qp(Rdmadev *rdev, RdmadevQp *qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevQp *iqp = (IbdevQp *)qp;
    struct ibv_qp_attr iattr = { 0 };
    uint32_t mask;
    int ret;

    mask = ibdev_qp_attr_mask(attr_mask);
    iattr.qp_state = ibv_qp_state(attr->qp_state);
    iattr.cur_qp_state = ibv_qp_state(attr->cur_qp_state);
    iattr.path_mtu = ibdev_mtu(attr->path_mtu);
    iattr.path_mig_state = ibv_mig_state(attr->path_mig_state);
    iattr.qkey = attr->qkey;
    iattr.rq_psn = attr->rq_psn;
    iattr.sq_psn = attr->sq_psn;
    iattr.dest_qp_num = attr->dest_qp_num;
    iattr.qp_access_flags = ibdev_access_flags(attr->qp_access_flags);
    iattr.cap.max_send_wr = attr->cap.max_send_wr;
    iattr.cap.max_recv_wr = attr->cap.max_recv_wr;
    iattr.cap.max_send_sge = attr->cap.max_send_sge;
    iattr.cap.max_recv_sge = attr->cap.max_recv_sge;
    iattr.cap.max_inline_data = attr->cap.max_inline_data;
ibdev_error_report("Modify QP mask 0x%x, state %d, timeout %d, path_mtu %d", mask, iattr.qp_state, attr->timeout, iattr.path_mtu);
    if (mask & IBV_QP_AV) {
        ret = ibdev_ah_attr(rdev, &attr->ah_attr, &iattr.ah_attr, NULL);
        if (ret) {
            return ret;
        }
    }

    if (mask & IBV_QP_ALT_PATH) {
        ret = ibdev_ah_attr(rdev, &attr->alt_ah_attr, &iattr.alt_ah_attr, NULL);
        if (ret) {
            return ret;
        }
    }
    iattr.pkey_index = attr->pkey_index;
    iattr.alt_pkey_index = attr->alt_pkey_index;
    iattr.en_sqd_async_notify = attr->en_sqd_async_notify;
    iattr.sq_draining = attr->sq_draining;
    iattr.max_rd_atomic = attr->max_rd_atomic;
    iattr.max_dest_rd_atomic = attr->max_dest_rd_atomic;
    iattr.min_rnr_timer = attr->min_rnr_timer;
    iattr.port_num = rdev->dev.u.ibdev.ibport; /* use host ibdev port */
    iattr.timeout = attr->timeout;
    iattr.retry_cnt = attr->retry_cnt;
    iattr.rnr_retry = attr->rnr_retry;
    iattr.alt_port_num = rdev->dev.u.ibdev.ibport; /* use host ibdev port */
    iattr.alt_timeout = attr->alt_timeout;
    iattr.rate_limit = attr->rate_limit;

    switch (qp->qp_type) {
    case RDMADEV_QPT_GSI:
        memcpy(&ibdev->gsi_attr, &iattr, sizeof(iattr));
        return 0;

    case RDMADEV_QPT_RC:
    case RDMADEV_QPT_UC:
    case RDMADEV_QPT_UD:
        break;

    case RDMADEV_QPT_SMI:
    default:
        ibdev_error_report("Modify unsupported QP type %s", rdmadev_qp_type(qp->qp_type));
        return -EINVAL;
    }

    ret = ibv_modify_qp(iqp->ibqp, &iattr, mask);
    if (ret) {
        ibdev_error_report("ibv_modify_qp failed: %m");
    }

    return ret;
}

static int ibdev_query_qp(Rdmadev *rdev, RdmadevQp *qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevQp *iqp = (IbdevQp *)qp;
    struct ibv_qp_attr iattr = { 0 };
    struct ibv_qp_init_attr init_attr = { 0 };
    uint32_t mask;
    int ret;

    switch (qp->qp_type) {
    case RDMADEV_QPT_GSI:
        memcpy(&iattr, &ibdev->gsi_attr, sizeof(iattr));
        break;

    case RDMADEV_QPT_RC:
    case RDMADEV_QPT_UC:
    case RDMADEV_QPT_UD:
        mask = ibdev_qp_attr_mask(attr_mask);
        ret = ibv_query_qp(iqp->ibqp, &iattr, mask, &init_attr);
        if (ret) {
            ibdev_error_report("ibv_query_qp failed: %m");
            return ret;
        }
        break;

    case RDMADEV_QPT_SMI:
    default:
        ibdev_error_report("Query unsupported QP type %s", rdmadev_qp_type(qp->qp_type));
        return -EINVAL;
    }

    attr->qp_state = ibv_qp_state_to(iattr.qp_state);
    attr->cur_qp_state = ibv_qp_state_to(iattr.cur_qp_state);
    attr->path_mig_state = ibv_mig_state_to(iattr.path_mig_state);
    attr->cap.max_send_wr = iattr.cap.max_send_wr;
    attr->cap.max_recv_wr = iattr.cap.max_recv_wr;
    attr->cap.max_send_sge = iattr.cap.max_send_sge;
    attr->cap.max_recv_sge = iattr.cap.max_recv_sge;
    attr->cap.max_inline_data = iattr.cap.max_inline_data;
    /* ah_attr & alt_ah_attr are required? */
    attr->path_mtu = ibdev_mtu_to(iattr.path_mtu);
    attr->qkey = iattr.qkey;
    attr->rq_psn = iattr.rq_psn;
    attr->sq_psn = iattr.sq_psn;
    attr->dest_qp_num = iattr.dest_qp_num;
    attr->qp_access_flags = iattr.qp_access_flags;
    attr->port_num = iattr.port_num;
    attr->alt_port_num = iattr.alt_port_num;
    attr->rate_limit = iattr.rate_limit;
    attr->pkey_index = iattr.pkey_index;
    attr->alt_pkey_index = iattr.alt_pkey_index;
    attr->en_sqd_async_notify = iattr.en_sqd_async_notify;
    attr->max_dest_rd_atomic = iattr.max_dest_rd_atomic;
    attr->max_rd_atomic = iattr.max_rd_atomic;
    attr->min_rnr_timer = iattr.min_rnr_timer;
    attr->retry_cnt = iattr.retry_cnt;
    attr->rnr_retry = iattr.rnr_retry;
    attr->sq_draining = iattr.sq_draining;
    attr->timeout = iattr.timeout;
    attr->alt_timeout = iattr.alt_timeout;

    return 0;
}

static int ibdev_fill_sge(Rdmadev *rdev, uint32_t pd_handle, struct ibv_sge *ibsges, RdmadevSge *sges, uint32_t num_sge, bool copy)
{
    for (unsigned int i = 0; i < num_sge; i++) {
        struct ibv_sge *ibsge = &ibsges[i];
        RdmadevSge *sge = &sges[i];
        RdmadevMr *mr = rdmadev_mr_by_lkey(rdev, pd_handle, sge->lkey);
        IbdevMr *imr = (IbdevMr *)mr;
        uint32_t off;

        if (!mr) {
            ibdev_error_report("Invalid lkey 0x%x of PD %d", sge->lkey, pd_handle);
            return -EINVAL;
        }

        if (mr->mr_type == RDMADEV_MR_DMA) {
            ibdev_error_report("DMA MR is not supported for normal QP");
            return -EACCES;
        }

        if ((sge->addr < mr->iova) || (sge->addr + sge->length > mr->iova + mr->length)) {
            ibdev_error_report("Invalid memory region");
            return -EACCES;
        }

        off = sge->addr - mr->iova;
        ibsge->addr = (uint64_t)imr->buffer + off;
        ibsge->length = sge->length;
        ibsge->lkey = mr->lkey;
        if (copy) {
            iov_to_buf(mr->sg, mr->sg_num, off, (void *)ibsge->addr, sge->length);
        }
    }

    return 0;
}

static int ibdev_post_recv_gsi(Rdmadev *rdev, RdmadevRecvWr *recv_wr)
{
    Ibdev *ibdev = IBDEV(rdev);
    IbdevGsiRecvWr *gsi_recv_wr = g_new0(IbdevGsiRecvWr, 1);

    gsi_recv_wr->wr = recv_wr;
    QTAILQ_INSERT_TAIL(&ibdev->gsi_recv_wrs, gsi_recv_wr, next);

        ibdev_error_report("GSI post recv");
    return 0;
}

static int ibdev_post_recv(Rdmadev *rdev, RdmadevQp *qp, RdmadevRecvWr *recv_wr)
{
    IbdevQp *iqp = (IbdevQp *)qp;
    struct ibv_recv_wr ibwr = { 0 };
    g_autofree struct ibv_sge *ibsges = NULL;
    struct ibv_recv_wr *bad_wr;
    int ret;

    switch (qp->qp_type) {
    case RDMADEV_QPT_GSI:
        return ibdev_post_recv_gsi(rdev, recv_wr);

    case RDMADEV_QPT_RC:
    case RDMADEV_QPT_UD:
        break;

    case RDMADEV_QPT_SMI:
    default:
        ibdev_error_report("Post recv on unsupported QP type %s", rdmadev_qp_type(qp->qp_type));
        return -EINVAL;
    }

    ibsges = g_new0(struct ibv_sge, recv_wr->num_sge);
    ibdev_fill_sge(rdev, qp->pd_handle, ibsges, recv_wr->sge, recv_wr->num_sge, false);

    ibwr.wr_id = (uint64_t)recv_wr;
    ibwr.sg_list = ibsges;
    ibwr.num_sge = recv_wr->num_sge;
    ibwr.next = NULL;

    ret = ibv_post_recv(iqp->ibqp, &ibwr, &bad_wr);
    if (ret) {
        ibdev_error_report("ibv_post_recv failed: %m");
    }

    return ret;
}

static inline int ibdev_post_send_rc(Rdmadev *rdev, struct ibv_send_wr *ibwr, RdmadevSendWr *send_wr)
{
    switch (send_wr->opcode) {
    case RDMADEV_WR_SEND:
        break;

    case RDMADEV_WR_SEND_WITH_IMM:
        ibwr->imm_data = send_wr->ex.imm_data;
        break;

    case RDMADEV_WR_SEND_WITH_INV:
        ibwr->invalidate_rkey = send_wr->ex.invalidate_rkey;
        break;

    case RDMADEV_WR_RDMA_READ_WITH_INV:
        ibwr->invalidate_rkey = send_wr->ex.invalidate_rkey;
        goto set_rdma;

    case RDMADEV_WR_RDMA_WRITE_WITH_IMM:
        ibwr->imm_data = send_wr->ex.imm_data;
        goto set_rdma;

set_rdma:
    case RDMADEV_WR_RDMA_READ:
    case RDMADEV_WR_RDMA_WRITE:
        ibwr->wr.rdma.remote_addr = send_wr->wr.rdma.remote_addr;
        ibwr->wr.rdma.rkey = send_wr->wr.rdma.rkey;
        break;

    case RDMADEV_WR_ATOMIC_CMP_AND_SWP:
    case RDMADEV_WR_ATOMIC_FETCH_AND_ADD:
    case RDMADEV_WR_ATOMIC_WRITE:
        ibwr->wr.atomic.remote_addr = send_wr->wr.atomic.remote_addr;
        ibwr->wr.atomic.compare_add = send_wr->wr.atomic.compare_add;
        ibwr->wr.atomic.swap = send_wr->wr.atomic.swap;
        ibwr->wr.atomic.rkey = send_wr->wr.atomic.rkey;
        break;

    case RDMADEV_WR_LOCAL_INV:
        ibwr->invalidate_rkey = send_wr->ex.invalidate_rkey;
        break;

    case RDMADEV_WR_REG_MR:
        ibwr->invalidate_rkey = send_wr->ex.invalidate_rkey;
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static inline int ibdev_post_send_ud(Rdmadev *rdev, struct ibv_send_wr *ibwr, RdmadevSendWr *send_wr)
{
    IbdevAh *ah;

    ah = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_AH, send_wr->wr.ud.ah_handle);
    if (!ah) {
        return -EINVAL;
    }

    switch (send_wr->opcode) {
    case RDMADEV_WR_SEND:
        break;
    case RDMADEV_WR_SEND_WITH_IMM:
        ibwr->imm_data = send_wr->ex.imm_data;
        break;
    case RDMADEV_WR_SEND_WITH_INV:
        ibwr->invalidate_rkey = send_wr->ex.invalidate_rkey;
        break;
    default:
        return -EINVAL;
    }

    ibwr->wr.ud.ah = ah->ibah;
    ibwr->wr.ud.remote_qpn = send_wr->wr.ud.remote_qpn;
    ibwr->wr.ud.remote_qkey = send_wr->wr.ud.remote_qkey;

    return 0;
}

static int ibdev_post_send(Rdmadev *rdev, RdmadevQp *qp, RdmadevSendWr *send_wr)
{
    IbdevQp *iqp = (IbdevQp *)qp;
    struct ibv_send_wr ibwr = { 0 };
    g_autofree struct ibv_sge *ibsges = NULL;
    struct ibv_send_wr *bad_wr;
    int ret;

    switch (qp->qp_type) {
    case RDMADEV_QPT_RC:
        ibdev_post_send_rc(rdev, &ibwr, send_wr);
        break;

    case RDMADEV_QPT_UD:
        ibdev_post_send_ud(rdev, &ibwr, send_wr);
        break;

    case RDMADEV_QPT_GSI:
        return ibdev_post_send_gsi(rdev, qp, send_wr);

    case RDMADEV_QPT_SMI:
    default:
        ibdev_error_report("Unsupported QP type %s", rdmadev_qp_type(qp->qp_type));
        return -EINVAL;
    }

    ibsges = g_new0(struct ibv_sge, send_wr->num_sge);
    ibdev_fill_sge(rdev, qp->pd_handle, ibsges, send_wr->sge, send_wr->num_sge, true);

    ibwr.wr_id = (uint64_t)send_wr;
    ibwr.next = NULL;
    ibwr.sg_list = ibsges;
    ibwr.num_sge = send_wr->num_sge;
    ibwr.opcode = ibv_wr_opcode(send_wr->opcode);
    ibwr.send_flags = ibv_send_flags(send_wr->send_flags);

    ret = ibv_post_send(iqp->ibqp, &ibwr, &bad_wr);
    if (ret) {
        ibdev_error_report("ibv_post_send failed: %m");
    }

    return ret;
}

static int ibdev_create_mr(Rdmadev *rdev, uint32_t pd_handle, RdmadevMrTypes mr_type, uint32_t access, uint32_t length, uint64_t iova, uint32_t sg_num, struct iovec *sg, uint32_t *mr_handle, uint32_t *lkey, uint32_t *rkey)
{
    unsigned int iaccess = ibdev_access_flags(access);
    IbdevMr *mr;
    IbdevPd *pd;
    int ret = -EIO;

    pd = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);
    if (!pd) {
        ibdev_error_report("invalid pd-handle %d", pd_handle);
        return -EINVAL;
    }

    mr = g_new0(IbdevMr, 1);
    if (mr_type == RDMADEV_MR_DMA) {
        length = 0;
        *lkey = IBDEV_DMA_MR_KEY;
        *rkey = IBDEV_DMA_MR_KEY;
    } else {
        mr->buffer = qemu_memalign(qemu_real_host_page_size(), length);
        mr->ibmr = ibv_reg_mr(pd->ibpd, mr->buffer, length, iaccess);
        if (!pd->ibpd) {
            ibdev_error_report("ibv_reg_mr failed: %m");
            goto free_mr;
        }

        *lkey = mr->ibmr->lkey;
        *rkey = mr->ibmr->rkey;
    }

    ret = __rdmadev_resource_alloc_at(rdev->res, RDMADEV_RESOURCE_MR, *lkey >> 8, mr);
    if (ret) {
        goto destroy_mr;
    }

    *mr_handle = *lkey >> 8;
    trace_ibdev_create_mr(*mr_handle, rdmadev_mr_type(mr_type), iova, length, mr->buffer);
    return 0;

destroy_mr:
    ibv_dereg_mr(mr->ibmr);

free_mr:
    g_free(mr->buffer);
    g_free(mr);

    return ret;
}

static int ibdev_destroy_mr(Rdmadev *rdev, uint32_t mr_handle)
{
    IbdevMr *mr = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_MR, mr_handle);

    if (!mr) {
        ibdev_warn_report("destroy invalid MR %d", mr_handle);
        return -EINVAL;
    }

    if (mr->rmr.mr_type != RDMADEV_MR_DMA) {
        assert(mr->ibmr);
        ibv_dereg_mr(mr->ibmr);
    }

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_MR, mr_handle);
}

static int ibdev_create_ah(Rdmadev *rdev, uint32_t pd_handle, RdmadevAhAttr *attr, uint32_t *ah_handle)
{
    IbdevAh *ah = g_new0(IbdevAh, 1);
    IbdevPd *pd;
    int ret;

    pd = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);
    if (!pd) {
        ibdev_error_report("Invalid pd-handle %d on creation AH", pd_handle);
        return -EINVAL;
    }

    ret = ibdev_ah_attr(rdev, attr, &ah->ibah_attr, &ah->sgid);
    if (ret) {
        goto free_ah;
    }

    ah->ibah = ibv_create_ah(pd->ibpd, &ah->ibah_attr);
    if (!ah->ibah) {
        ibdev_error_report("Failed to create AH: %m");
        goto free_ah;
    }

    ret = __rdmadev_resource_alloc(rdev->res, RDMADEV_RESOURCE_AH, ah_handle, ah);
    if (ret) {
        goto destroy_ah;
    }

    return 0;

destroy_ah:
    ibv_destroy_ah(ah->ibah);

free_ah:
    g_free(ah);
    return ret;
}

static int ibdev_destroy_ah(Rdmadev *rdev, uint32_t ah_handle)
{
    IbdevAh *ah = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_AH, ah_handle);

    if (!ah) {
        ibdev_warn_report("Dealloc invalid AH %d", ah_handle);
        return -EINVAL;
    }

    assert(ah->ibah);
    ibv_destroy_ah(ah->ibah);

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_AH, ah_handle);
}

static int ibdev_create_srq(Rdmadev *rdev, uint32_t pd_handle, uint32_t max_wr, uint32_t max_sge, uint32_t srq_limit, uint32_t *srq_handle)
{
    IbdevSrq *srq = g_new0(IbdevSrq, 1);
    IbdevPd *pd;
    struct ibv_srq_init_attr attr = { 0 };
    int ret;

    pd = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_PD, pd_handle);
    if (!pd) {
        ibdev_error_report("Failed to create SRQ, invalid PD %d", pd_handle);
        return -EINVAL;
    }

    attr.srq_context = srq;
    attr.attr.max_wr = max_wr;
    attr.attr.max_sge = max_sge;
    attr.attr.srq_limit = srq_limit;
    srq->ibsrq = ibv_create_srq(pd->ibpd, &attr);
    if (!srq->ibsrq) {
        ibdev_error_report("Failed to create SRQ: %m");
        ret = -errno;
        goto free_srq;
    }

    ret = __rdmadev_resource_alloc(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle, srq);
    if (ret) {
        goto destroy_srq;
    }

    return 0;

destroy_srq:
    ibv_destroy_srq(srq->ibsrq);

free_srq:
    g_free(srq);

    return ret;
}

static int ibdev_query_srq(Rdmadev *rdev, uint32_t srq_handle, RdmadevSrqAttr *attr)
{
    struct ibv_srq_attr iattr = { 0 };
    IbdevSrq *srq;
    int ret;

    srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
    if (!srq) {
        ibdev_warn_report("Query invalid SRQ %d", srq_handle);
        return -EINVAL;
    }

    assert(srq->ibsrq);
    ret = ibv_query_srq(srq->ibsrq, &iattr);
    if (ret) {
        ibdev_error_report("ibv_query_srq failed: %m");
        return ret;
    }

    attr->max_wr = iattr.max_wr;
    attr->max_sge = iattr.max_sge;
    attr->srq_limit = iattr.srq_limit;

    return 0;
}

static int ibdev_modify_srq(Rdmadev *rdev, uint32_t srq_handle, uint32_t attr_mask, RdmadevSrqAttr *attr)
{
    struct ibv_srq_attr iattr = { 0 };
    IbdevSrq *srq;
    int mask = ibdev_srq_attr_mask(attr_mask);
    int ret;

    srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
    if (!srq) {
        ibdev_warn_report("Query invalid SRQ %d", srq_handle);
        return -EINVAL;
    }

    assert(srq->ibsrq);

    iattr.max_wr = attr->max_wr;
    iattr.srq_limit = attr->srq_limit;

    ret = ibv_modify_srq(srq->ibsrq, &iattr, mask);
    if (ret) {
        ibdev_error_report("ibv_modify_srq failed: %m");
    }

    return 0;

}

static int ibdev_destroy_srq(Rdmadev *rdev, uint32_t srq_handle)
{
    IbdevSrq *srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);

    if (!srq) {
        ibdev_warn_report("Dealloc invalid SRQ %d", srq_handle);
        return -EINVAL;
    }

    assert(srq->ibsrq);
    ibv_destroy_srq(srq->ibsrq);

    return __rdmadev_resource_dealloc(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
}

static int ibdev_post_srq_recv(Rdmadev *rdev, RdmadevSrq *srq, RdmadevRecvWr *recv_wr)
{
    IbdevSrq *isrq = (IbdevSrq *)srq;
    struct ibv_recv_wr ibwr = { 0 };
    g_autofree struct ibv_sge *ibsges = NULL;
    struct ibv_recv_wr *bad_wr;
    int ret;

    ibsges = g_new0(struct ibv_sge, recv_wr->num_sge);
    ibdev_fill_sge(rdev, srq->pd_handle, ibsges, recv_wr->sge, recv_wr->num_sge, false);

    ibwr.wr_id = (uint64_t)recv_wr;
    ibwr.sg_list = ibsges;
    ibwr.num_sge = recv_wr->num_sge;
    ibwr.next = NULL;

    ret = ibv_post_srq_recv(isrq->ibsrq, &ibwr, &bad_wr);
    if (ret) {
        ibdev_error_report("ibv_post_srq_recv failed: %m");
    }

    return 0;
}

static void ibdev_instance_init(Object *obj)
{
    Ibdev *ibdev = IBDEV(obj);

    printf("always: %s, %d, ibdev %p\n", __func__, __LINE__, ibdev->rdev.dev.u.ibdev.ibdev);
}

static void ibdev_instance_finalize(Object *obj)
{
    Ibdev *ibdev = IBDEV(obj);

    printf("always: %s, %d, ibdev %p\n", __func__, __LINE__, ibdev->rdev.dev.u.ibdev.ibdev);
}

#define IBDEV_PROP_INT(_type, _var, _func)                           \
    static void ibdev_prop_get_##_func(Object *obj, Visitor *v,      \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Ibdev *ibdev = IBDEV(obj);                                   \
        _type##_t value = _var;                                      \
        visit_type_##_type(v, name, &value, errp);                   \
    }                                                                \
                                                                     \
    static void ibdev_prop_set_##_func(Object *obj, Visitor *v,      \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Ibdev *ibdev = IBDEV(obj);                                   \
        _type##_t value;                                             \
    if (!visit_type_##_type(v, name, &value, errp)) {                \
        return;                                                      \
    }                                                                \
        _var = value;                                                \
    }

#define IBDEV_PROP_STR(_var, _func)                                  \
    static char *ibdev_prop_get_##_func(Object *obj, Error **errp)   \
    {                                                                \
        Ibdev *ibdev = IBDEV(obj);                                   \
        return g_strdup(_var);                                       \
    }                                                                \
                                                                     \
    static void ibdev_prop_set_##_func(Object *obj,                  \
        const char *value, Error **errp)                             \
    {                                                                \
        Ibdev *ibdev = IBDEV(obj);                                   \
        if (_var) {                                                  \
            error_setg(errp, #_func " property already set");        \
            return;                                                  \
        }                                                            \
        _var = g_strdup(value);                                      \
    }

IBDEV_PROP_STR(ibdev->rdev.dev.u.ibdev.mad_chardev, mad_chardev)
IBDEV_PROP_STR(ibdev->rdev.dev.u.ibdev.netdev, netdev)
IBDEV_PROP_STR(ibdev->rdev.dev.u.ibdev.ibdev, ibdev)
IBDEV_PROP_INT(uint32, ibdev->rdev.dev.u.ibdev.ibport, ibport)

static void ibdev_class_init(ObjectClass *oc, void *data)
{
    RdmadevClass *rdc = RDMADEV_CLASS(oc);

    object_class_property_add_str(oc, "mad-chardev", ibdev_prop_get_mad_chardev, ibdev_prop_set_mad_chardev);
    object_class_property_add_str(oc, "netdev", ibdev_prop_get_netdev, ibdev_prop_set_netdev);
    object_class_property_add_str(oc, "ibdev", ibdev_prop_get_ibdev, ibdev_prop_set_ibdev);
    object_class_property_add(oc, "ibport", "uint32",
                              ibdev_prop_get_ibport,
                              ibdev_prop_set_ibport,
                              NULL, NULL);

    printf("always: %s, %d\n", __func__, __LINE__);
    rdc->init_dev = ibdev_init_dev;
    rdc->finalize_dev = ibdev_finalize_dev;

    rdc->init_port = ibdev_init_port;
    rdc->finalize_port = ibdev_finalize_port;

    rdc->add_gid = ibdev_add_gid;
    rdc->del_gid = ibdev_del_gid;

    rdc->alloc_uc = ibdev_alloc_uc;
    rdc->dealloc_uc = ibdev_dealloc_uc;

    rdc->alloc_pd = ibdev_alloc_pd;
    rdc->dealloc_pd = ibdev_dealloc_pd;

    rdc->create_cq = ibdev_create_cq;
    rdc->destroy_cq = ibdev_destroy_cq;
    rdc->req_notify_cq = ibdev_req_notify_cq;
    rdc->poll_cq = ibdev_poll_cq;

    rdc->create_qp = ibdev_create_qp;
    rdc->destroy_qp = ibdev_destroy_qp;
    rdc->modify_qp = ibdev_modify_qp;
    rdc->query_qp = ibdev_query_qp;

    rdc->post_recv = ibdev_post_recv;
    rdc->post_send = ibdev_post_send;

    rdc->create_mr = ibdev_create_mr;
    rdc->destroy_mr = ibdev_destroy_mr;

    rdc->create_ah = ibdev_create_ah;
    rdc->destroy_ah = ibdev_destroy_ah;

    rdc->create_srq = ibdev_create_srq;
    rdc->query_srq = ibdev_query_srq;
    rdc->modify_srq = ibdev_modify_srq;
    rdc->destroy_srq = ibdev_destroy_srq;
    rdc->post_srq_recv = ibdev_post_srq_recv;
}

static const TypeInfo ibdev_type_info = {
    .name = TYPE_IBDEV,
    .parent = TYPE_RDMADEV,
    .instance_size = sizeof(Ibdev),
    .instance_init = ibdev_instance_init,
    .instance_finalize = ibdev_instance_finalize,
    .class_init = ibdev_class_init,
};

static void ibdev_register_types(void)
{
    printf("always: %s, %d\n", __func__, __LINE__);
    type_register_static(&ibdev_type_info);
}

type_init(ibdev_register_types);
