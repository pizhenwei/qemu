/*
 * QEMU RDMA Backend Support
 *
 * Copyright (c) 2024 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_RDMA_H
#define RDMA_RDMA_H

#include "qapi/qapi-types-rdma.h"
#include "qemu/queue.h"
#include "qom/object.h"
#include "rdma/rdma-types.h"
#include "sysemu/dma.h"
#include "net/net.h"

#define TYPE_RDMADEV "rdmadev"
OBJECT_DECLARE_TYPE(Rdmadev, RdmadevClass, RDMADEV)

struct Rdmadev {
    Object parent_obj;
    const char *name; /* cache object_get_canonical_path_component() */

    /* main rdmadev data structure described by rdma.json */
    RdmaDev dev;
    /* device attributes */
    RdmaDevAttr dev_attr;
    /* port1 attributes */
    RdmaPortAttr port_attr;

    /* hardware device opaque pointer */
    void *hwdev;

    /* CQ completion callback function */
    void (*cq_comp)(void *hwdev, RdmadevWc *wc, int cq, void *opaque);

    /* DMA map/unmap callback function */
    void *(*dma_map)(void *hwdev, dma_addr_t addr, dma_addr_t len);
    void (*dma_unmap)(void *hwdev, void *buffer, dma_addr_t len);

    /* rdma devices linked list */
    QTAILQ_ENTRY(Rdmadev) next;
};

struct RdmadevClass {
    ObjectClass parent_class;

    int (*init_dev)(Rdmadev *rdev);
    void (*finalize_dev)(Rdmadev *rdev);

    int (*init_port)(Rdmadev *rdev, RdmaPortAttr *port, NICState *nic);
    void (*finalize_port)(Rdmadev *rdev, uint8_t port);
    int (*query_port)(Rdmadev *rdev, uint8_t port, RdmaPortAttr *attr);

    int (*add_gid)(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid, RdmaGidType type);
    int (*del_gid)(Rdmadev *rdev, uint8_t port, uint8_t index);
    int (*get_gid)(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid);

    int (*alloc_uc)(Rdmadev *rdev, int uc, void *opaque);
    int (*dealloc_uc)(Rdmadev *rdev, int uc);

    int (*alloc_pd)(Rdmadev *rdev, int uc, void *opaque);
    int (*dealloc_pd)(Rdmadev *rdev, int pd);

    int (*create_cq)(Rdmadev *rdev, int uc, int cqe, int comp_vector, void *opaque);
    int (*destroy_cq)(Rdmadev *rdev, int cq);
    int (*req_notify_cq)(Rdmadev *rdev, int cq, int solicited_only);
    int (*poll_cq)(Rdmadev *rdev, int cq);
    int (*cq_ctx)(Rdmadev *rdev, int qp, void **opaque);

    int (*create_qp)(Rdmadev *rdev, int pd, uint32_t flags, int srq, int send_cq, int recv_cq, RdmadevQpCap *cap, RdmadevQpType qp_type, void *opaque);
    int (*destroy_qp)(Rdmadev *rdev, int qp);
    int (*modify_qp)(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr);
    int (*query_qp)(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr);
    int (*qp_ctx)(Rdmadev *rdev, int qp, void **opaque);
    int (*qp_type)(Rdmadev *rdev, int qp);

    int (*post_recv)(Rdmadev *rdev, int qp, RdmadevRecvWr *recv_wr);
    int (*post_send)(Rdmadev *rdev, int qp, RdmadevSendWr *send_wr);

    int (*create_mr)(Rdmadev *rdev, int pd, RdmadevMrTypes mr_type, uint32_t access, uint32_t length, uint64_t iova, uint32_t sg_num, struct iovec *sg, uint32_t *lkey, uint32_t *rkey, void *opaque);
    int (*destroy_mr)(Rdmadev *rdev, int mr);

    int (*create_ah)(Rdmadev *rdev, int pd, RdmadevAhAttr *attr, void *opaque);
    int (*destroy_ah)(Rdmadev *rdev, int ah);

#if 0
    int (*create_srq)(Rdmadev *rdev, uint32_t pd_handle, uint32_t max_wr, uint32_t max_sge, uint32_t srq_limit, uint32_t *srq_handle);
    int (*query_srq)(Rdmadev *rdev, uint32_t srq_handle, RdmadevSrqAttr *attr);
    int (*modify_srq)(Rdmadev *rdev, uint32_t srq_handle, uint32_t attr_mask, RdmadevSrqAttr *attr);
    int (*destroy_srq)(Rdmadev *rdev, uint32_t srq_handle);
    int (*post_srq_recv)(Rdmadev *rdev, RdmadevSrq *srq, RdmadevRecvWr *recv_wr);
#endif
};

/**
 * rdmadev_name:
 * @rdev: Rdmadev handle
 *
 * Get RDMA device name
 *
 * Return: object name
 */
static inline const char *rdmadev_name(Rdmadev *rdev)
{
    return object_get_canonical_path_component(&rdev->parent_obj);
}

int rdmadev_init(Rdmadev *rdev);
void rdmadev_finalize(Rdmadev *rdev);

int rdmadev_init_port(Rdmadev *rdev, uint8_t port, NICState *nic);

int rdmadev_query_port(Rdmadev *rdev, uint8_t port, RdmaPortAttr *attr);

int rdmadev_query_pkey(Rdmadev *rdev, uint8_t port, uint16_t index);

int rdmadev_add_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid, RdmaGidType type);
int rdmadev_del_gid(Rdmadev *rdev, uint8_t port, uint8_t index);
int rdmadev_get_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid);

/**
 * rdmadev_alloc_uc:
 * @rdev: Rdmadev handle
 * @uc: specify UC (>= 0), or any unused one (-1)
 * @opaque: opaque user data
 *
 * Allocate an ucontext
 *
 * Return: UC handle (>= 0) on success; -errno on failure
 */
int rdmadev_alloc_uc(Rdmadev *rdev, int uc, void *opaque);

/**
 * rdmadev_dealloc_uc:
 * @rdev: Rdmadev handle
 * @uc: ucontext handle
 *
 * Free an ucontext
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_dealloc_uc(Rdmadev *rdev, int uc);

/**
 * rdmadev_alloc_pd:
 * @rdev: Rdmadev handle
 * @uc: ucontext handle
 * @opaque: opaque user data
 *
 * Allocate a protection domain
 *
 * Return: PD handle (>= 0) on success; -errno on failure
 */
int rdmadev_alloc_pd(Rdmadev *rdev, int uc, void *opaque);

/**
 * rdmadev_dealloc_pd:
 * @rdev: Rdmadev handle
 * @pd: protection domain handle
 *
 * Free a protection domain
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_dealloc_pd(Rdmadev *rdev, int pd);

/**
 * rdmadev_create_cq:
 * @rdev: Rdmadev handle
 * @uc: ucontext handle
 * @cqe: minimum number of entries required for CQ
 * @comp_vector: consumer-supplied context returned for completion event
 * @opaque: opaque user data
 *
 * Allocate a completion queue
 *
 * Return: CQ handle (>= 0) on success; -errno on failure
 */
int rdmadev_create_cq(Rdmadev *rdev, int uc, int cqe, int comp_vector, void *opaque);

/**
 * rdmadev_destroy_cq:
 * @rdev: Rdmadev handle
 * @cq: completion queue handle
 *
 * Destroy a completion queue
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_destroy_cq(Rdmadev *rdev, int cq);

/**
 * rdmadev_req_notify_cq:
 * @rdev: Rdmadev handle
 * @cq: completion queue handle
 * @solicited_only: if non-zero, an event will be generated only for the next
 *                  solicited CQ entry. If zero, any CQ entry, solicited or not,
 *                  will generate an event.
 *
 * Request completion notification on a CQ
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_req_notify_cq(Rdmadev *rdev, int cq, int solicited_only);

/**
 * rdmadev_poll_cq:
 * @rdev: Rdmadev handle
 * @cq: completion queue handle
 *
 * Poll a CQ for (possibly multiple) completions
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_poll_cq(Rdmadev *rdev, int cq);

/**
 * rdmadev_cq_ctx:
 * @rdev: Rdmadev handle
 * @cq: completion queue handle
 * @opaque: opaque user data
 *
 * Get opaque user data of a complection queue
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_cq_ctx(Rdmadev *rdev, int cq, void **opaque);

#if 0
int rdmadev_create_srq(Rdmadev *rdev, int pd_handle, int max_wr, int max_sge, int srq_limit, void *opaque, int *srq_handle);
int rdmadev_query_srq(Rdmadev *rdev, int srq_handle, RdmadevSrqAttr *attr);
int rdmadev_modify_srq(Rdmadev *rdev, int srq_handle, int attr_mask, RdmadevSrqAttr *attr);
int rdmadev_destroy_srq(Rdmadev *rdev, int srq_handle);
int rdmadev_post_srq_recv(Rdmadev *rdev, int srq_handle, RdmadevRecvWr *recv_wr);
#endif

/**
 * rdmadev_create_qp:
 * @rdev: Rdmadev handle
 * @pd: protection domain handle
 * @flags: mask of @RdmadevQpFlags
 * @srq: specify SRQ handle if (flags & RDMADEV_QP_SRQ)
 * @send_cq: sending completion queue handle
 * @recv_cq: receiving completion queue handle
 * @cap: QP capabilities of @RdmadevQpCap
 * @qp_type: QP transport service type of @RdmadevQpType
 * @opaque: opaque user data
 *
 * Create a queue pair
 *
 * Return: QP handle (>= 0) on success; -errno on failure
 */
int rdmadev_create_qp(Rdmadev *rdev, int pd, uint32_t flags, int srq, int send_cq, int recv_cq, RdmadevQpCap *cap, RdmadevQpType qp_type, void *opaque);

/**
 * rdmadev_destroy_qp:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 *
 * Destroy a queue pair
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_destroy_qp(Rdmadev *rdev, int qp);

/**
 * rdmadev_modify_qp:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 * @attr_mask: mask of @RdmadevQpAttrMask
 * @attr: attributes of @RdmadevQpAttr
 *
 * Modify a queue pair
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_modify_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr);

/**
 * rdmadev_query_qp:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 * @attr_mask: mask of @RdmadevQpAttrMask
 * @attr: attributes of @RdmadevQpAttr
 *
 * Query a queue pair
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_query_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr);

/**
 * rdmadev_qp_ctx:
 * @rdev: Rdmadev handle
 * @cq: completion queue handle
 * @opaque: opaque user data
 *
 * Get opaque user data of a QP
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_qp_ctx(Rdmadev *rdev, int qp, void **opaque);

/**
 * rdmadev_qp_type:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 *
 * Get QP type of @RdmadevQpType
 *
 * Return: >= 0 on success; -errno on failure
 */
int rdmadev_qp_type(Rdmadev *rdev, int qp);

/**
 * rdmadev_post_recv:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 * @recv_wr: receiving work request
 *
 * Post a work request to a receive queue
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_post_recv(Rdmadev *rdev, int qp, RdmadevRecvWr *recv_wr);

/**
 * rdmadev_post_send:
 * @rdev: Rdmadev handle
 * @qp: QP handle
 * @send_wr: sending work request
 *
 * Post a work request to a send queue
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_post_send(Rdmadev *rdev, int qp, RdmadevSendWr *send_wr);

static inline bool rdmadev_qp_is_srq(Rdmadev *rdev, int qp)
{
    RdmadevQpAttr attr = { 0 };
    rdmadev_query_qp(rdev, qp, RDMADEV_QP_FLAGS, &attr);

    return attr.flags & RDMADEV_QP_SRQ;
}

/**
 * rdmadev_create_mr:
 * @rdev: Rdmadev handle
 * @pd: protection domain handle
 * @mr_type: memory region type of @RdmadevMrTypes
 * @access: mask of @RdmadevAccessFlags
 * @length: the length of MR
 * @iova: the start address of MR
 * @sg_num: the count of @sg
 * @sg: scatter gather list of host VA & length
 * @lkey: local KEY
 * @rkey: remote KEY
 *
 * Create a memory region
 *
 * Return: MR handle (>= 0) on success; -errno on failure
 */
int rdmadev_create_mr(Rdmadev *rdev, int pd, RdmadevMrTypes mr_type, uint32_t access, uint32_t length, uint64_t iova, uint32_t sg_num, struct iovec *sg, uint32_t *lkey, uint32_t *rkey, void *opaque);

/**
 * rdmadev_destroy_mr:
 * @rdev: Rdmadev handle
 * @mr: memory region handle
 *
 * Destroy a memory region
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_destroy_mr(Rdmadev *rdev, int mr);

int rdmadev_reg_mr(Rdmadev *rdev, int mr, uint32_t lkey, uint32_t rkey, uint32_t access, uint32_t length, uint64_t iova, int sg_num, struct iovec *sg);

/**
 * rdmadev_create_ah:
 * @rdev: Rdmadev handle
 * @pd: protection domain handle
 * @attr: attributes of @RdmadevAhAttr
 *
 * Create an address handle
 *
 * Return: AH handle (>= 0) on success; -errno on failure
 */
int rdmadev_create_ah(Rdmadev *rdev, int pd, RdmadevAhAttr *attr, void *opaque);

/**
 * rdmadev_destroy_ah:
 * @rdev: Rdmadev handle
 * @ah: address handle
 *
 * Destroy an address handle
 *
 * Return: 0 on success; -errno on failure
 */
int rdmadev_destroy_ah(Rdmadev *rdev, int ah);

#endif
