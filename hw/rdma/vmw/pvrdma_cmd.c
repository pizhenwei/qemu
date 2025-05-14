/*
 * QEMU VMW PVRDMA - Command channel
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
#include "pvrdma-types.h"
#include "trace.h"

static int pvrdma_query_port(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_query_port *cmd = &req->query_port;
    struct pvrdma_port_attr *attrs = &resp->query_port_resp.attrs;
    RdmaPortAttr rattr;

    if (cmd->port_num != 1) {
        return -EINVAL;
    }

    if (rdmadev_query_port(rdev, cmd->port_num, &rattr)) {
        return -ENODEV;
    }

    attrs->state = dev->func0->device_active ? PVRDMA_PORT_ACTIVE : PVRDMA_PORT_DOWN;
    attrs->max_mtu = pvrdma_mtu(rattr.max_mtu);
    attrs->active_mtu = pvrdma_mtu(rattr.active_mtu);
    attrs->gid_tbl_len = rattr.gid_tbl_len;
    attrs->port_cap_flags = pvrdma_port_cap_flags(rattr.port_cap_flags);
    attrs->max_msg_sz = rattr.max_msg_sz;
    attrs->pkey_tbl_len = 1;
    attrs->max_vl_num = rattr.max_vl_num;
    attrs->active_width = PVRDMA_WIDTH_1X;
    attrs->active_speed = pvrdma_speed(rattr.active_speed);
    attrs->phys_state = 5; /* LINK UP */

    return 0;
}

static int pvrdma_query_pkey(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    struct pvrdma_cmd_query_pkey *cmd = &req->query_pkey;

    if (cmd->port_num != 1) {
        return -EINVAL;
    }

    if (cmd->index > PVRDMA_PKEYS) {
        return -EINVAL;
    }

    resp->query_pkey_resp.pkey = PVRDMA_PKEY;
    return 0;
}

static int pvrdma_create_pd(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_create_pd *cmd = &req->create_pd;
    int ret;

    ret = rdmadev_alloc_pd(rdev, cmd->ctx_handle, NULL);
    if (ret < 0) {
        return ret;
    }

    resp->create_pd_resp.pd_handle = ret;
    return 0;
}

static int pvrdma_destroy_pd(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_pd *cmd = &req->destroy_pd;

    return rdmadev_dealloc_pd(rdev, cmd->pd_handle);
}

static struct iovec *pvrdma_mr_map_pages(PVRDMADev *dev, dma_addr_t dir_addr, uint32_t npages)
{
    PCIDevice *pdev = PCI_DEVICE(dev);
    struct iovec *sg = NULL;
    uint64_t *dir, *tbl;
    g_autofree void **pages = NULL;

    if (npages > PVRDMA_DMA_PAGES) {
        pvrdma_error_report("MR maximum pages on a single directory must not exceed %d\n", PVRDMA_DMA_PAGES);
        return NULL;
    }

    dir = pvrdma_pci_dma_map_page(pdev, dir_addr);
    if (!dir) {
        pvrdma_error_report("Failed to map to page directory for MR");
        return NULL;
    }

    /* We support only one page table for a ring */
    tbl = pvrdma_pci_dma_map_page(pdev, dir[0]);
    if (!tbl) {
        pvrdma_error_report("Failed to map to page table for MR");
        goto out_free_dir;
    }

    pages = pvrdma_pci_map_pages(pdev, tbl, npages);
    if (!pages) {
        pvrdma_error_report("Failed to map pages for MR");
        goto out_free_tbl;
    }

    sg = g_new0(struct iovec, npages);
    for (unsigned int i = 0; i < npages; i++) {
        struct iovec *iov = &sg[i];

        iov->iov_base = pages[i];
        iov->iov_len = qemu_target_page_size();
    }

out_free_tbl:
    pvrdma_pci_dma_unmap_page(pdev, tbl);

out_free_dir:
    pvrdma_pci_dma_unmap_page(pdev, dir);

    return sg;
}

static int pvrdma_create_mr(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_create_mr *cmd = &req->create_mr;
    struct pvrdma_cmd_create_mr_resp *rsp = &resp->create_mr_resp;
    uint64_t iova = cmd->start;
    uint32_t flags = cmd->flags;
    uint32_t pd_handle = cmd->pd_handle;
    uint32_t access;
    uint32_t length;
    uint32_t lkey, rkey;
    uint32_t sg_num;
    struct iovec *sg;
    RdmadevMrTypes mr_type;
    int ret;

    if (cmd->length > ((uint32_t)-1)) {
        pvrdma_warn_report("MR size 0x%"PRIx64", exceeds uint32", cmd->length);
        return -ENOMEM;
    }

    if (flags & PVRDMA_MR_FLAG_DMA) {
        mr_type = RDMADEV_MR_DMA;
        sg_num = 0;
        sg = NULL;
    } else if (flags & PVRDMA_MR_FLAG_FRMR) {
        mr_type = RDMADEV_MR_FRMR;
        sg_num = cmd->nchunks;
        sg = NULL;
    } else {
        mr_type = RDMADEV_MR_MEM;
        sg_num = cmd->nchunks;
        sg = pvrdma_mr_map_pages(dev, cmd->pdir_dma, cmd->nchunks);
        if (!sg) {
            return -EIO;
        }
    }

    access = pvrdma_access_flags_to(cmd->access_flags);
    length = cmd->length;

    ret = rdmadev_create_mr(rdev, pd_handle, mr_type, access, length, iova, sg_num, sg, &lkey, &rkey, NULL);
    if (ret < 0) {
        return ret;
    }

    rsp->mr_handle = ret;
    rsp->lkey = lkey;
    rsp->rkey = rkey;

    return 0;
}

static int pvrdma_destroy_mr(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_mr *cmd = &req->destroy_mr;

    return rdmadev_destroy_mr(rdev, cmd->mr_handle);
}

static int pvrdma_create_cq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    PCIDevice *pdev = PCI_DEVICE(dev);
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_create_cq *cmd = &req->create_cq;
    uint64_t pdir_dma = cmd->pdir_dma;
    uint32_t cqe = cmd->cqe;
    char name[PVRDMA_RING_NAME_SIZE] = { 0 };
    PvrdmaRing *ring;
    int ret;

    if (cqe > pvrdma_max_cqe(dev) || !is_power_of_2(cqe)) {
        pvrdma_error_report("Unsupport CQE %d", cqe);
        return -EINVAL;
    }

    snprintf(name, PVRDMA_RING_NAME_SIZE, "cq-ring-%" PRIx64, pdir_dma);
    ring = g_malloc0(sizeof(*ring));
    ret = pvrdma_ring_init(ring, name, pdev, cqe, sizeof(struct pvrdma_cqe), pdir_dma, cmd->nchunks, 0);
    if (ret) {
        pvrdma_error_report("Failed to init CQ ring on %"PRIx64, pdir_dma);
        goto free_mem;
    }

    /* a single comp vector supported, always 0 */
    ret = rdmadev_create_cq(rdev, cmd->ctx_handle, cqe, 0, ring);
    if (ret < 0) {
        goto free_ring;
    }

    resp->create_cq_resp.cq_handle = ret;
    resp->create_cq_resp.cqe = cqe;

    return 0;

free_ring:
    pvrdma_ring_free(ring);

free_mem:
    g_free(ring);

    return ret;
}

static int pvrdma_destroy_cq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_cq *cmd = &req->destroy_cq;
    PvrdmaRing *ring;
    int cq = cmd->cq_handle;
    int ret;

    ret = rdmadev_cq_ctx(rdev, cq, (void **)&ring);
    if (ret) {
        pvrdma_error_report("Failed to destroy invalid CQ %d", cq);
        return ret;
    }

    ret = rdmadev_destroy_cq(rdev, cq);
    if (ret) {
        return ret;
    }

    pvrdma_ring_free(ring);
    g_free(ring);

    return 0;
}

static void pvrdma_free_qp_rings(PvrdmaRing *ring, bool is_srq)
{
    PvrdmaRing *sring = ring;
    PvrdmaRing *rring;

    pvrdma_ring_free(sring);
    if (!is_srq) {
        rring = sring + 1;
        pvrdma_ring_free(rring);
    }

    g_free(ring);
}

static int pvrdma_create_qp(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    PCIDevice *pdev = PCI_DEVICE(dev);
    struct pvrdma_cmd_create_qp *cmd = &req->create_qp;
    struct pvrdma_cmd_create_qp_resp *rsp = &resp->create_qp_resp;
    uint64_t pdir_dma = cmd->pdir_dma;
    PvrdmaRing *sring = NULL, *rring = NULL;
    char name[PVRDMA_RING_NAME_SIZE] = { 0 };
    uint32_t send_wqe_sz, recv_wqe_sz;
    uint32_t flags = 0;
    RdmadevQpType qp_type;
    RdmadevQpCap cap;
    int ret;

    qp_type = pvrdma_qp_type_to(cmd->qp_type);
    if (qp_type == RDMADEV_QPT_MAX) {
        pvrdma_error_report("Unsupport qp_type %d", cmd->qp_type);
        return -EINVAL;
    }

    if (!is_power_of_2(cmd->max_send_wr)) {
        pvrdma_error_report("Unsupport max_send_wr");
        return -EINVAL;
    }

    if (!cmd->is_srq && !is_power_of_2(cmd->max_recv_wr)) {
        pvrdma_error_report("Unsupport max_recv_wr");
        return -EINVAL;
    }

    sring = g_new0(PvrdmaRing, 1 + !cmd->is_srq);

    snprintf(name, PVRDMA_RING_NAME_SIZE, "qp-sring-%" PRIx64, pdir_dma);
    send_wqe_sz = pow2ceil(sizeof(struct pvrdma_sq_wqe_hdr) + sizeof(struct pvrdma_sge) * cmd->max_send_sge);
    /* cmd->send_chunks does NOT contains ring_state page */
    ret = pvrdma_ring_init(sring, name, pdev, cmd->max_send_wr, send_wqe_sz, pdir_dma, cmd->send_chunks + 1, 0);
    if (ret) {
        pvrdma_error_report("Failed to init QP %s", name);
        goto free_rings;
    }

    if (cmd->is_srq) {
        flags |= RDMADEV_QP_SRQ;
    } else {
        rring = sring + 1;
        snprintf(name, PVRDMA_RING_NAME_SIZE, "qp-rring-%" PRIx64, pdir_dma);
        recv_wqe_sz = pow2ceil(sizeof(struct pvrdma_rq_wqe_hdr) + sizeof(struct pvrdma_sge) * cmd->max_recv_sge);
        ret = pvrdma_ring_init(rring, name, pdev, cmd->max_recv_wr, recv_wqe_sz, pdir_dma, cmd->total_chunks, cmd->send_chunks);
        if (ret) {
            pvrdma_error_report("Failed to init QP %s", name);
            rring = NULL;
            goto free_rings;
        }
    }

    cap.max_send_wr = cmd->max_send_wr;
    cap.max_recv_wr = cmd->max_recv_wr;
    cap.max_send_sge = cmd->max_send_sge;
    cap.max_recv_sge = cmd->max_recv_sge;
    cap.max_inline_data = cmd->max_inline_data;

    flags |= cmd->sq_sig_all ? RDMADEV_QP_SIG_ALL : 0;
    ret = rdmadev_create_qp(rdev, cmd->pd_handle, flags, cmd->srq_handle, cmd->send_cq_handle, cmd->recv_cq_handle, &cap, qp_type, sring);
    if (ret < 0) {
        pvrdma_error_report("Failed to create QP %d", ret);
        goto free_rings;
    }

    rsp->qpn = ret;
    rsp->max_send_wr = cap.max_send_wr;
    rsp->max_recv_wr = cap.max_recv_wr;
    rsp->max_send_sge = cap.max_send_sge;
    rsp->max_recv_sge = cap.max_recv_sge;
    rsp->max_inline_data = cap.max_inline_data;

    return 0;

free_rings:
    pvrdma_free_qp_rings(sring, cmd->is_srq);

    return ret;
}

static int pvrdma_destroy_qp(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_qp *cmd = &req->destroy_qp;
    PvrdmaRing *ring;
    bool is_srq = rdmadev_qp_is_srq(rdev, cmd->qp_handle);
    int ret;

    ret = rdmadev_qp_ctx(rdev, cmd->qp_handle, (void **)&ring);
    if (ret) {
        pvrdma_error_report("Failed to destroy QP Rings");
        return ret;
    }

    ret = rdmadev_destroy_qp(rdev, cmd->qp_handle);
    if (ret) {
        pvrdma_error_report("Failed to destroy QP");
        return ret;
    }

    pvrdma_free_qp_rings(ring, is_srq);

    return 0;
}

static inline void pvrdma_ah_attr_to(RdmadevAhAttr *rah, struct pvrdma_ah_attr *ah)
{
    RdmadevGlobalRoute *rgrh = &rah->grh;
    struct pvrdma_global_route *grh = &ah->grh;

    QEMU_BUILD_BUG_ON(sizeof(ah->grh.dgid) != sizeof(rah->grh.dgid));
    memcpy(rgrh->dgid.raw, grh->dgid.raw, sizeof(rgrh->dgid.raw));
    rgrh->flow_label = grh->flow_label;
    rgrh->sgid_index = grh->sgid_index;
    rgrh->hop_limit = grh->hop_limit;
    rgrh->traffic_class = grh->traffic_class;

    rah->dlid = ah->dlid;
    rah->sl = ah->sl;
    rah->src_path_bits = ah->src_path_bits;
    rah->static_rate = ah->static_rate;
    rah->port_num = ah->port_num;
    memcpy(rah->dmac, ah->dmac, 6);
}

static int pvrdma_modify_qp(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    struct pvrdma_cmd_modify_qp *cmd = &req->modify_qp;
    struct pvrdma_qp_attr *attrs = &cmd->attrs;
    RdmadevQpAttr rattr = { 0 };
    uint32_t mask;

    mask = pvrdma_qp_attr_mask_to(cmd->attr_mask);
    rattr.qp_state = pvrdma_qp_state_to(attrs->qp_state);
    rattr.cur_qp_state = pvrdma_qp_state_to(attrs->cur_qp_state);
    rattr.path_mtu = pvrdma_mtu_to(attrs->path_mtu);
    rattr.path_mig_state = pvrdma_mig_state_to(attrs->path_mig_state);
    rattr.qkey = attrs->qkey;
    rattr.rq_psn = attrs->rq_psn;
    rattr.sq_psn = attrs->sq_psn;
    rattr.dest_qp_num = attrs->dest_qp_num;
    rattr.qp_access_flags = pvrdma_access_flags_to(attrs->qp_access_flags);
    rattr.pkey_index = attrs->pkey_index;
    rattr.alt_pkey_index = attrs->alt_pkey_index;
    rattr.en_sqd_async_notify = attrs->en_sqd_async_notify;
    rattr.sq_draining = attrs->sq_draining;
    rattr.max_rd_atomic = attrs->max_rd_atomic;
    rattr.max_dest_rd_atomic = attrs->max_dest_rd_atomic;
    rattr.min_rnr_timer = attrs->min_rnr_timer;
    rattr.port_num = attrs->port_num;
    rattr.timeout = attrs->timeout;
    rattr.retry_cnt = attrs->retry_cnt;
    rattr.rnr_retry = attrs->rnr_retry;
    rattr.alt_port_num = attrs->alt_port_num;
    rattr.alt_timeout = attrs->alt_timeout;
    rattr.cap.max_send_wr = attrs->cap.max_send_wr;
    rattr.cap.max_recv_wr = attrs->cap.max_recv_wr;
    rattr.cap.max_send_sge = attrs->cap.max_send_sge;
    rattr.cap.max_recv_sge = attrs->cap.max_recv_sge;
    rattr.cap.max_inline_data = attrs->cap.max_inline_data;
    pvrdma_ah_attr_to(&rattr.ah_attr, &attrs->ah_attr);
    pvrdma_ah_attr_to(&rattr.alt_ah_attr, &attrs->alt_ah_attr);


    return rdmadev_modify_qp(dev->rdev, cmd->qp_handle, mask, &rattr);
}

static int pvrdma_query_qp(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    struct pvrdma_cmd_query_qp *cmd = &req->query_qp;
    struct pvrdma_qp_attr *attrs = &resp->query_qp_resp.attrs;
    RdmadevQpAttr rattr = { 0 };
    uint32_t mask = pvrdma_qp_attr_mask_to(cmd->attr_mask);
    int ret;

    ret = rdmadev_query_qp(dev->rdev, cmd->qp_handle, mask, &rattr);
    attrs->qp_state = pvrdma_qp_state(rattr.qp_state);
    attrs->cur_qp_state = pvrdma_qp_state(rattr.cur_qp_state);
    attrs->path_mtu = pvrdma_mtu(rattr.path_mtu);
    attrs->path_mig_state = pvrdma_mig_state(rattr.path_mig_state);
    attrs->qkey = rattr.qkey;
    attrs->rq_psn = rattr.rq_psn;
    attrs->sq_psn = rattr.sq_psn;
    attrs->dest_qp_num = rattr.dest_qp_num;
    attrs->qp_access_flags = rattr.qp_access_flags;
    attrs->pkey_index = rattr.pkey_index;
    attrs->alt_pkey_index = rattr.alt_pkey_index;
    attrs->en_sqd_async_notify = rattr.en_sqd_async_notify;
    attrs->sq_draining = rattr.sq_draining;
    attrs->max_rd_atomic = rattr.max_rd_atomic;
    attrs->max_dest_rd_atomic = rattr.max_dest_rd_atomic;
    attrs->min_rnr_timer = rattr.min_rnr_timer;
    attrs->port_num = rattr.port_num;
    attrs->timeout = rattr.timeout;
    attrs->retry_cnt = rattr.retry_cnt;
    attrs->rnr_retry = rattr.rnr_retry;
    attrs->alt_port_num = rattr.alt_port_num;
    attrs->alt_timeout = rattr.alt_timeout;
    attrs->cap.max_send_wr = rattr.cap.max_send_wr;
    attrs->cap.max_recv_wr = rattr.cap.max_recv_wr;
    attrs->cap.max_send_sge = rattr.cap.max_send_sge;
    attrs->cap.max_recv_sge = rattr.cap.max_recv_sge;
    attrs->cap.max_inline_data = rattr.cap.max_inline_data;

    return ret;
}

static int pvrdma_create_uc(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    int ret;

    /* TODO: Need to make sure pfn64 is between bar start address and
     * bsd+RDMA_BAR2_UAR_SIZE */
    ret = rdmadev_alloc_uc(rdev, 0, NULL);
    if (ret < 0) {
        return ret;
    }

    resp->create_uc_resp.ctx_handle = ret;
    return 0;
}

static int pvrdma_destroy_uc(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_uc *cmd = &req->destroy_uc;

    return rdmadev_dealloc_uc(rdev, cmd->ctx_handle);
}

static int pvrdma_create_bind(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    struct pvrdma_cmd_create_bind *cmd = &req->create_bind;
    uint8_t index = cmd->index;
    RdmaGidType gid_type;

    gid_type = pvrdma_gid_type_to(cmd->gid_type);
    if (gid_type == RDMADEV_GID_TYPE__MAX) {
        pvrdma_warn_report("Unknown gid-type %d", cmd->gid_type);
        return -EINVAL;
    }

    return rdmadev_add_gid(dev->rdev, 1, index, cmd->new_gid, gid_type);
}

#if 0
static int pvrdma_create_srq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    PCIDevice *pdev = PCI_DEVICE(dev);
    struct pvrdma_cmd_create_srq *cmd = &req->create_srq;
    uint64_t pdir_dma = cmd->pdir_dma;
    PvrdmaRing *ring = NULL;
    char name[PVRDMA_RING_NAME_SIZE] = { 0 };
    uint32_t max_wr = cmd->attrs.max_wr;
    uint32_t max_sge = cmd->attrs.max_sge;
    uint32_t srq_limit = cmd->attrs.srq_limit;
    uint32_t wqe_sz;
    uint32_t srq_handle;
    int ret;

    ring = g_new0(PvrdmaRing, 1);
    snprintf(name, PVRDMA_RING_NAME_SIZE, "srq-%" PRIx64, pdir_dma);
    wqe_sz = pow2ceil(sizeof(struct pvrdma_rq_wqe_hdr) + sizeof(struct pvrdma_sge) * max_sge);
    ret = pvrdma_ring_init(ring, name, pdev, max_wr, wqe_sz, pdir_dma, cmd->nchunks, 0);
    if (ret) {
        pvrdma_error_report("Failed to init SRQ %s", name);
        return ret;
    }

    ret = rdmadev_create_srq(rdev, cmd->pd_handle, max_wr, max_sge, srq_limit, ring, &srq_handle);
    if (ret) {
        goto free_ring;
    }

    resp->create_srq_resp.srqn = srq_handle;

    return 0;

free_ring:
    pvrdma_ring_free(ring);
    g_free(ring);

    return ret;
}

static int pvrdma_query_srq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_query_srq *cmd = &req->query_srq;
    RdmadevSrqAttr rattr;
    struct pvrdma_srq_attr *attr = &resp->query_srq_resp.attrs;
    int ret;

    ret = rdmadev_query_srq(rdev, cmd->srq_handle, &rattr);
    if (ret) {
        return ret;
    }

    attr->max_wr = rattr.max_wr;
    attr->max_sge = rattr.max_sge;
    attr->srq_limit = rattr.srq_limit;

    return 0;
}

static int pvrdma_modify_srq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_modify_srq *cmd = &req->modify_srq;
    struct pvrdma_srq_attr *attrs = &cmd->attrs;
    RdmadevSrqAttr rattr = { 0 };
    uint32_t mask;

    rattr.max_wr = attrs->max_wr;
    rattr.srq_limit = attrs->srq_limit;
    mask = pvrdma_srq_attr_mask_to(cmd->attr_mask);

    return rdmadev_modify_srq(rdev, cmd->srq_handle, mask, &rattr);
}

static int pvrdma_destroy_srq(PVRDMADev *dev, union pvrdma_cmd_req *req,
                      union pvrdma_cmd_resp *resp)
{
    Rdmadev *rdev = dev->rdev;
    struct pvrdma_cmd_destroy_srq *cmd = &req->destroy_srq;
    uint32_t srq_handle = cmd->srq_handle;
    RdmadevSrq *srq;

    srq = rdmadev_get_srq(rdev, srq_handle);
    if (!srq) {
        pvrdma_warn_report("Failed to destroy SRQ %d", srq_handle);
        return -EINVAL;
    }

    pvrdma_ring_free(srq->opaque);
    rdmadev_destroy_srq(rdev, cmd->srq_handle);
    return 0;
}
#endif

typedef int (*pvrdma_exec_func) (PVRDMADev *dev, union pvrdma_cmd_req *req, union pvrdma_cmd_resp *resp);

static struct pvrdma_cmd_handler {
    uint32_t cmd;
    uint32_t ack;
    const char *name;
    pvrdma_exec_func exec;
}  pvrdma_cmd_handlers[] = {
    { PVRDMA_CMD_QUERY_PORT,   PVRDMA_CMD_QUERY_PORT_RESP,
      "query-port", pvrdma_query_port },
    { PVRDMA_CMD_QUERY_PKEY,   PVRDMA_CMD_QUERY_PKEY_RESP,
      "query-pkey", pvrdma_query_pkey },
    { PVRDMA_CMD_CREATE_PD,    PVRDMA_CMD_CREATE_PD_RESP,
      "create-pd", pvrdma_create_pd },
    { PVRDMA_CMD_DESTROY_PD,   PVRDMA_CMD_DESTROY_PD_RESP_NOOP,
      "destroy-pd", pvrdma_destroy_pd },
    { PVRDMA_CMD_CREATE_MR,    PVRDMA_CMD_CREATE_MR_RESP,
      "create-mr", pvrdma_create_mr },
    { PVRDMA_CMD_DESTROY_MR,   PVRDMA_CMD_DESTROY_MR_RESP_NOOP,
      "destroy-mr", pvrdma_destroy_mr },
    { PVRDMA_CMD_CREATE_CQ,    PVRDMA_CMD_CREATE_CQ_RESP,
      "create-cq", pvrdma_create_cq },
    { PVRDMA_CMD_RESIZE_CQ,    PVRDMA_CMD_RESIZE_CQ_RESP,
      "resize-cq", NULL },
    { PVRDMA_CMD_DESTROY_CQ,   PVRDMA_CMD_DESTROY_CQ_RESP_NOOP,
      "destroy-cq", pvrdma_destroy_cq },
    { PVRDMA_CMD_CREATE_QP,    PVRDMA_CMD_CREATE_QP_RESP,
      "create-qp", pvrdma_create_qp },
    { PVRDMA_CMD_MODIFY_QP,    PVRDMA_CMD_MODIFY_QP_RESP,
      "modify-qp", pvrdma_modify_qp },
    { PVRDMA_CMD_QUERY_QP,     PVRDMA_CMD_QUERY_QP_RESP,
      "query-qp", pvrdma_query_qp },
    { PVRDMA_CMD_DESTROY_QP,   PVRDMA_CMD_DESTROY_QP_RESP,
      "destroy-qp", pvrdma_destroy_qp },
    { PVRDMA_CMD_CREATE_UC,    PVRDMA_CMD_CREATE_UC_RESP,
      "create-uc", pvrdma_create_uc },
    { PVRDMA_CMD_DESTROY_UC,   PVRDMA_CMD_DESTROY_UC_RESP_NOOP,
      "destroy-uc", pvrdma_destroy_uc },
    { PVRDMA_CMD_CREATE_BIND,  PVRDMA_CMD_CREATE_BIND_RESP_NOOP,
      "create-bind", pvrdma_create_bind },
    { PVRDMA_CMD_DESTROY_BIND, PVRDMA_CMD_DESTROY_BIND_RESP_NOOP,
      "destroy-bind", NULL },
#if 0
    { PVRDMA_CMD_CREATE_SRQ,   PVRDMA_CMD_CREATE_SRQ_RESP,
      "create-srq", pvrdma_create_srq },
    { PVRDMA_CMD_MODIFY_SRQ,   PVRDMA_CMD_MODIFY_SRQ_RESP,
      "modify-srq", pvrdma_modify_srq },
    { PVRDMA_CMD_QUERY_SRQ,    PVRDMA_CMD_QUERY_SRQ_RESP,
      "query-srq", pvrdma_query_srq },
    { PVRDMA_CMD_DESTROY_SRQ,  PVRDMA_CMD_DESTROY_SRQ_RESP,
      "destroy-srq", pvrdma_destroy_srq }
#endif
};

int pvrdma_exec_cmd(PVRDMADev *dev)
{
    union pvrdma_cmd_req *req = dev->cmd_slot;
    union pvrdma_cmd_resp *resp = dev->resp_slot;
    struct pvrdma_cmd_handler *handler;
    pvrdma_exec_func exec;
    uint32_t cmd = req->hdr.cmd;
    const char *cmdname = "Unknown";
    int ret;

    if (cmd >= PVRDMA_CMD_MAX) {
        pvrdma_error_report("Unknown command %d", cmd);
        ret = -EINVAL;
        goto out;
    }

    handler = &pvrdma_cmd_handlers[cmd];
    assert(cmd == handler->cmd);

    cmdname = pvrdma_cmd_handlers[cmd].name;
    exec = handler->exec;
    if (!exec) {
        pvrdma_error_report("Command %s is not implemented yet", cmdname);
        ret = -ENOTSUP;
        goto out;
    }

    /* clear response buffer */
    memset(resp, 0x00, sizeof(*resp));

    ret = exec(dev, req, resp);
    resp->hdr.response = req->hdr.response;
    resp->hdr.ack = pvrdma_cmd_handlers[cmd].ack;
    resp->hdr.err = ret;

out:
    trace_pvrdma_exec_cmd(cmdname, cmd, ret);

    return ret;
}
