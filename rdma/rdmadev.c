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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "rdma/rdma.h"
#include "rdma/rdma-types.h"
#include "rdmadev.h"
#include "trace.h"

static QTAILQ_HEAD(, Rdmadev) rdmadevs;

int rdmadev_init_port(Rdmadev *rdev, uint8_t port, NICState *nic)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    RdmaPortAttr *attr = &rdev->port_attr;
    int ret;

    if (port != 1) {
        rdmadev_error_report(rdev, "port 1 is supported only");
        return -EINVAL;
    }

    attr->index = port;
    ret = rdc->init_port(rdev, attr, nic);
    if (ret) {
        return ret;
    }

    trace_rdmadev_init_port(rdev->name, port, qemu_get_queue(nic)->name);
    return 0;
}

int rdmadev_init(Rdmadev *rdev)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    if (rdev->dev_attr.phys_port_cnt != 1) {
        rdmadev_error_report(rdev, "1 dev-phys-port-cnt is supported only");
        return -EINVAL;
    }

    if (!rdc->init_dev) {
        return -ENOTSUP;
    }

    rdev->name = rdmadev_name(rdev);
    return rdc->init_dev(rdev);
}

void rdmadev_finalize(Rdmadev *rdev)
{
}

int rdmadev_add_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid, RdmaGidType type)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    if (type >= RDMADEV_GID_TYPE__MAX || !gid) {
        return -EINVAL;
    }

    return rdc->add_gid(rdev, port, index, gid, type);
}

int rdmadev_del_gid(Rdmadev *rdev, uint8_t port, uint8_t index)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->del_gid(rdev, port, index);
}

int rdmadev_get_gid(Rdmadev *rdev, uint8_t port, uint8_t index, uint8_t *gid)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->get_gid(rdev, port, index, gid);
}

int rdmadev_query_port(Rdmadev *rdev, uint8_t port, RdmaPortAttr *attr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->query_port(rdev, port, attr);
}

int rdmadev_alloc_uc(Rdmadev *rdev, int uc, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->alloc_uc(rdev, uc, opaque);
    trace_rdmadev_alloc_uc(rdev->name, uc, ret);

    return ret;
}

int rdmadev_dealloc_uc(Rdmadev *rdev, int uc)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    trace_rdmadev_dealloc_uc(rdev->name, uc);
    return rdc->dealloc_uc(rdev, uc);
}

int rdmadev_alloc_pd(Rdmadev *rdev, int uc, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->alloc_pd(rdev, uc, opaque);
    trace_rdmadev_alloc_pd(rdev->name, uc, ret);

    return ret;
}

int rdmadev_dealloc_pd(Rdmadev *rdev, int pd)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->dealloc_pd(rdev, pd);
    trace_rdmadev_dealloc_pd(rdev->name, pd, ret);

    return ret;
}

int rdmadev_create_cq(Rdmadev *rdev, int uc, int cqe, int comp_vector, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->create_cq(rdev, uc, cqe, comp_vector, opaque);
    trace_rdmadev_create_cq(rdev->name, uc, cqe, comp_vector, ret);

    return ret;
}

int rdmadev_destroy_cq(Rdmadev *rdev, int cq)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->destroy_cq(rdev, cq);
    trace_rdmadev_destroy_cq(rdev->name, cq, ret);

    return ret;
}

int rdmadev_req_notify_cq(Rdmadev *rdev, int cq, int solicited_only)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->req_notify_cq(rdev, cq, solicited_only);
    trace_rdmadev_req_notify_cq(rdev->name, cq, solicited_only, ret);

    return ret;
}

int rdmadev_poll_cq(Rdmadev *rdev, int cq)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    trace_rdmadev_poll_cq(rdev->name, cq);
    return rdc->poll_cq(rdev, cq);
}

int rdmadev_cq_ctx(Rdmadev *rdev, int cq, void **opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->cq_ctx(rdev, cq, opaque);
}

int rdmadev_create_qp(Rdmadev *rdev, int pd, uint32_t flags, int srq, int send_cq, int recv_cq, RdmadevQpCap *cap, RdmadevQpType qp_type, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    assert(qp_type < RDMADEV_QPT_MAX);
    ret = rdc->create_qp(rdev, pd, flags, srq, send_cq, recv_cq, cap, qp_type, opaque);
    trace_rdmadev_create_qp(rdev->name, pd, flags, srq, send_cq, recv_cq, rdmadev_qp_type_str(qp_type), ret);

    return ret;
}

int rdmadev_destroy_qp(Rdmadev *rdev, int qp)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->destroy_qp(rdev, qp);
    trace_rdmadev_destroy_qp(rdev->name, qp);

    return ret;
}

int rdmadev_modify_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->modify_qp(rdev, qp, attr_mask, attr);
    trace_rdmadev_modify_qp(rdev->name, qp, attr_mask, ret);

    return ret;
}

int rdmadev_query_qp(Rdmadev *rdev, int qp, uint32_t attr_mask, RdmadevQpAttr *attr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->query_qp(rdev, qp, attr_mask, attr);
    trace_rdmadev_query_qp(rdev->name, qp, attr_mask, ret);

    return ret;
}

int rdmadev_qp_ctx(Rdmadev *rdev, int qp, void **opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->qp_ctx(rdev, qp, opaque);
}

int rdmadev_qp_type(Rdmadev *rdev, int qp)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->qp_type(rdev, qp);
    if (ret >= 0) {
        assert(ret < RDMADEV_QPT_MAX);
    }

    return ret;
}

int rdmadev_post_recv(Rdmadev *rdev, int qp, RdmadevRecvWr *recv_wr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->post_recv(rdev, qp, recv_wr);
    trace_rdmadev_post_recv(rdev->name, qp, recv_wr->num_sge, ret);

    return ret;
}

int rdmadev_post_send(Rdmadev *rdev, int qp, RdmadevSendWr *send_wr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->post_send(rdev, qp, send_wr);
    trace_rdmadev_post_send(rdev->name, qp, send_wr->num_sge, ret);

    return ret;
}

int rdmadev_create_mr(Rdmadev *rdev, int pd, RdmadevMrTypes mr_type, uint32_t access, uint32_t length, uint64_t iova, uint32_t sg_num, struct iovec *sg, uint32_t *lkey, uint32_t *rkey, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    assert(mr_type < RDMADEV_MR_MAX);

    ret = rdc->create_mr(rdev, pd, mr_type, access, length, iova, sg_num, sg, lkey, rkey, opaque);

    trace_rdmadev_create_mr(rdev->name, pd, rdmadev_mr_type(mr_type), access, length, iova, sg_num, *lkey, *rkey, ret);

    return ret;
}

int rdmadev_destroy_mr(Rdmadev *rdev, int mr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->destroy_mr(rdev, mr);
    trace_rdmadev_destroy_mr(rdev->name, mr, ret);

    return ret;
}

int rdmadev_reg_mr(Rdmadev *rdev, int mr, uint32_t lkey, uint32_t rkey, uint32_t access, uint32_t length, uint64_t iova, int sg_num, struct iovec *sg)
{
    return 0;
}

int rdmadev_create_ah(Rdmadev *rdev, int pd, RdmadevAhAttr *attr, void *opaque)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->create_ah(rdev, pd, attr, opaque);
    trace_rdmadev_create_ah(rdev->name, pd, ret);

    return ret;
}

int rdmadev_destroy_ah(Rdmadev *rdev, int ah)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    int ret;

    ret = rdc->destroy_ah(rdev, ah);
    trace_rdmadev_destroy_ah(rdev->name, ah, ret);

    return ret;
}

#if 0
int rdmadev_create_srq(Rdmadev *rdev, uint32_t pd_handle, uint32_t max_wr, uint32_t max_sge, uint32_t srq_limit, void *opaque, uint32_t *srq_handle)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    RdmadevSrq *srq;
    int ret;

    ret = rdc->create_srq(rdev, pd_handle, max_wr, max_sge, srq_limit, srq_handle);
    trace_rdmadev_create_srq(*srq_handle, pd_handle, ret);
    if (ret) {
        return ret;
    }

    srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, *srq_handle);
    srq->pd_handle = pd_handle;
    srq->opaque = opaque;

    return ret;
}

int rdmadev_query_srq(Rdmadev *rdev, uint32_t srq_handle, RdmadevSrqAttr *attr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->query_srq(rdev, srq_handle, attr);
}

int rdmadev_modify_srq(Rdmadev *rdev, uint32_t srq_handle, uint32_t attr_mask, RdmadevSrqAttr *attr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    return rdc->modify_srq(rdev, srq_handle, attr_mask, attr);
}

int rdmadev_destroy_srq(Rdmadev *rdev, uint32_t srq_handle)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);

    trace_rdmadev_destroy_srq(srq_handle);
    return rdc->destroy_srq(rdev, srq_handle);
}

int rdmadev_post_srq_recv(Rdmadev *rdev, uint32_t srq_handle, RdmadevRecvWr *recv_wr)
{
    RdmadevClass *rdc = RDMADEV_GET_CLASS(rdev);
    RdmadevSrq *srq;

    trace_rdmadev_post_srq_recv(srq_handle, recv_wr->num_sge);
    srq = __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
    if (!srq) {
        return -EINVAL;
    }

    return rdc->post_srq_recv(rdev, srq, recv_wr);
}

RdmadevSrq *rdmadev_get_srq(Rdmadev *rdev, uint32_t srq_handle)
{
    return __rdmadev_resource_get(rdev->res, RDMADEV_RESOURCE_SRQ, srq_handle);
}
#endif

#define RDMADEV_PROP_DEV_PHYS_PORT_CNT "dev-phys-port-cnt"
#define RDMADEV_PROP_DEV_MAX_UC "dev-max-uc"
#define RDMADEV_PROP_DEV_MAX_QP "dev-max-qp"
#define RDMADEV_PROP_DEV_MAX_QP_WR "dev-max-qp-wr"
#define RDMADEV_PROP_DEV_MAX_SGE "dev-max-sge"
#define RDMADEV_PROP_DEV_MAX_SGE_RD "dev-max-sge-rd"
#define RDMADEV_PROP_DEV_MAX_CQ "dev-max-cq"
#define RDMADEV_PROP_DEV_MAX_CQE "dev-max-cqe"
#define RDMADEV_PROP_DEV_MAX_MR "dev-max-mr"
#define RDMADEV_PROP_DEV_MAX_PD "dev-max-pd"
#define RDMADEV_PROP_DEV_MAX_QP_RD_ATOM "dev-max-qp-rd-atom"
#define RDMADEV_PROP_DEV_MAX_RES_RD_ATOM "dev-max-res-rd-atom"
#define RDMADEV_PROP_DEV_MAX_QP_INIT_RD_ATOM "dev-max-qp-init-rd-atom"
#define RDMADEV_PROP_DEV_MAX_AH "dev-max-ah"
#define RDMADEV_PROP_DEV_MAX_MR_SIZE "dev-max-mr-size"
#define RDMADEV_PROP_DEV_MAX_SRQ "dev-max-srq"
#define RDMADEV_PROP_DEV_MAX_SRQ_WR "dev-max-srq-wr"
#define RDMADEV_PROP_DEV_MAX_SRQ_SGE "dev-max-srq-sge"
#define RDMADEV_PROP_DEV_MAX_PKEYS "dev-max-pkeys"

#define RDMADEV_PROP_PORT_MAX_MSG_SZ "port-max-msg-sz"

static void rdmadev_instance_init(Object *obj)
{
    Rdmadev *rdev = RDMADEV(obj);

    /* set default rdmadev properties */
    object_property_set_int(obj, RDMADEV_PROP_DEV_PHYS_PORT_CNT, 1, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_UC, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_QP, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_QP_WR, 4096, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_SGE, 32, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_SGE_RD, 32, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_CQ, 2048, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_CQE, 4096, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_MR, 4096, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_PD, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_QP_RD_ATOM, 128, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_RES_RD_ATOM, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_QP_INIT_RD_ATOM, 128, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_AH, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_MR_SIZE, 16 * 1024 * 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_SRQ, 1024, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_SRQ_WR, 4096, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_SRQ_SGE, 16, NULL);
    object_property_set_int(obj, RDMADEV_PROP_DEV_MAX_PKEYS, 1, NULL);

    object_property_set_int(obj, RDMADEV_PROP_PORT_MAX_MSG_SZ, 4 * 1024 * 1024, NULL);

    QTAILQ_INSERT_TAIL(&rdmadevs, rdev, next);
}

static void rdmadev_instance_finalize(Object *obj)
{
    Rdmadev *rdev = RDMADEV(obj);

    printf("always: %s, %d\n", __func__, __LINE__);
    QTAILQ_REMOVE(&rdmadevs, rdev, next);
}

#define RDMADEV_PROP_INT(_type, _var, _func)                         \
    static void rdmadev_prop_get_##_func(Object *obj, Visitor *v,    \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Rdmadev *rdev = RDMADEV(obj);                                \
        _type##_t value = _var;                                      \
        visit_type_##_type(v, name, &value, errp);                   \
    }                                                                \
                                                                     \
    static void rdmadev_prop_set_##_func(Object *obj, Visitor *v,    \
        const char *name, void *opaque, Error **errp)                \
    {                                                                \
        Rdmadev *rdev = RDMADEV(obj);                                \
        _type##_t value;                                             \
    if (!visit_type_##_type(v, name, &value, errp)) {                \
        return;                                                      \
    }                                                                \
        _var = value;                                                \
    }

#define RDMADEV_PROP_STR(_var, _func)                                \
    static char *rdmadev_prop_get_##_func(Object *obj, Error **errp) \
    {                                                                \
        Rdmadev *rdev = RDMADEV(obj);                                \
        return g_strdup(_var);                                       \
    }                                                                \
                                                                     \
    static void rdmadev_prop_set_##_func(Object *obj,                \
        const char *value, Error **errp)                             \
    {                                                                \
        Rdmadev *rdev = RDMADEV(obj);                                \
        if (_var) {                                                  \
            error_setg(errp, #_func " property already set");        \
            return;                                                  \
        }                                                            \
        _var = g_strdup(value);                                      \
    }

RDMADEV_PROP_INT(uint8, rdev->dev_attr.phys_port_cnt, dev_phys_port_cnt)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_uc, dev_max_uc)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_qp, dev_max_qp)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_qp_wr, dev_max_qp_wr)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_sge, dev_max_sge)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_sge_rd, dev_max_sge_rd)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_cq, dev_max_cq)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_cqe, dev_max_cqe)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_mr, dev_max_mr)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_pd, dev_max_pd)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_qp_rd_atom, dev_max_qp_rd_atom)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_res_rd_atom, dev_max_res_rd_atom)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_qp_init_rd_atom, dev_max_qp_init_rd_atom)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_ah, dev_max_ah)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_mr_size, dev_max_mr_size)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_srq, dev_max_srq)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_srq_wr, dev_max_srq_wr)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_srq_sge, dev_max_srq_sge)
RDMADEV_PROP_INT(uint32, rdev->dev_attr.max_pkeys, dev_max_pkeys)
RDMADEV_PROP_INT(uint32, rdev->port_attr.max_msg_sz, port_max_msg_sz)

static void rdmadev_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add(oc, RDMADEV_PROP_DEV_PHYS_PORT_CNT, "uint8",
                              rdmadev_prop_get_dev_phys_port_cnt,
                              rdmadev_prop_set_dev_phys_port_cnt,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_UC, "uint32",
                              rdmadev_prop_get_dev_max_uc,
                              rdmadev_prop_set_dev_max_uc,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_QP, "uint32",
                              rdmadev_prop_get_dev_max_qp,
                              rdmadev_prop_set_dev_max_qp,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_QP_WR, "uint32",
                              rdmadev_prop_get_dev_max_qp_wr,
                              rdmadev_prop_set_dev_max_qp_wr,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_SGE, "uint32",
                              rdmadev_prop_get_dev_max_sge,
                              rdmadev_prop_set_dev_max_sge,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_SGE_RD, "uint32",
                              rdmadev_prop_get_dev_max_sge_rd,
                              rdmadev_prop_set_dev_max_sge_rd,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_CQ, "uint32",
                              rdmadev_prop_get_dev_max_cq,
                              rdmadev_prop_set_dev_max_cq,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_CQE, "uint32",
                              rdmadev_prop_get_dev_max_cqe,
                              rdmadev_prop_set_dev_max_cqe,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_MR, "uint32",
                              rdmadev_prop_get_dev_max_mr,
                              rdmadev_prop_set_dev_max_mr,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_PD, "uint32",
                              rdmadev_prop_get_dev_max_pd,
                              rdmadev_prop_set_dev_max_pd,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_QP_RD_ATOM, "uint32",
                              rdmadev_prop_get_dev_max_qp_rd_atom,
                              rdmadev_prop_set_dev_max_qp_rd_atom,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_RES_RD_ATOM, "uint32",
                              rdmadev_prop_get_dev_max_res_rd_atom,
                              rdmadev_prop_set_dev_max_res_rd_atom,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_QP_INIT_RD_ATOM, "uint32",
                              rdmadev_prop_get_dev_max_qp_init_rd_atom,
                              rdmadev_prop_set_dev_max_qp_init_rd_atom,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_AH, "uint32",
                              rdmadev_prop_get_dev_max_ah,
                              rdmadev_prop_set_dev_max_ah,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_MR_SIZE, "uint64",
                              rdmadev_prop_get_dev_max_mr_size,
                              rdmadev_prop_set_dev_max_mr_size,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_SRQ, "uint32",
                              rdmadev_prop_get_dev_max_srq,
                              rdmadev_prop_set_dev_max_srq,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_SRQ_WR, "uint32",
                              rdmadev_prop_get_dev_max_srq_wr,
                              rdmadev_prop_set_dev_max_srq_wr,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_SRQ_SGE, "uint32",
                              rdmadev_prop_get_dev_max_srq_sge,
                              rdmadev_prop_set_dev_max_srq_sge,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_DEV_MAX_PKEYS, "uint32",
                              rdmadev_prop_get_dev_max_pkeys,
                              rdmadev_prop_set_dev_max_pkeys,
                              NULL, NULL);
    object_class_property_add(oc, RDMADEV_PROP_PORT_MAX_MSG_SZ, "uint32",
                              rdmadev_prop_get_port_max_msg_sz,
                              rdmadev_prop_set_port_max_msg_sz,
                              NULL, NULL);

    QTAILQ_INIT(&rdmadevs);
}

static const TypeInfo rdmadev_type_info = {
    .name = TYPE_RDMADEV,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(Rdmadev),
    .instance_init = rdmadev_instance_init,
    .instance_finalize = rdmadev_instance_finalize,
    .abstract = true,
    .class_size = sizeof(RdmadevClass),
    .class_init = rdmadev_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void rdmadev_register_types(void)
{
    printf("always: %s, %d\n", __func__, __LINE__);
    type_register_static(&rdmadev_type_info);
}

type_init(rdmadev_register_types);
