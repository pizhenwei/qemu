/*
 * QEMU RDMA host IB device types.
 *
 * Copyright (c) 2024 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_IBDEV_TYPES_H
#define RDMA_IBDEV_TYPES_H

#include <infiniband/verbs.h>

#include "rdma/rdma-types.h"
#include "rdma/rdma-utils.h"

static inline uint32_t ibdev_device_cap(uint32_t caps)
{
    static RdmadevFlags devcap_tbls[] = {
        { IBV_DEVICE_RESIZE_MAX_WR, RDMADEV_DEVICE_RESIZE_MAX_WR },
        { IBV_DEVICE_BAD_PKEY_CNTR, RDMADEV_DEVICE_BAD_PKEY_CNTR },
        { IBV_DEVICE_BAD_QKEY_CNTR, RDMADEV_DEVICE_BAD_QKEY_CNTR },
        { IBV_DEVICE_RAW_MULTI, RDMADEV_DEVICE_RAW_MULTI },
        { IBV_DEVICE_AUTO_PATH_MIG, RDMADEV_DEVICE_AUTO_PATH_MIG },
        { IBV_DEVICE_CHANGE_PHY_PORT, RDMADEV_DEVICE_CHANGE_PHY_PORT },
        { IBV_DEVICE_UD_AV_PORT_ENFORCE, RDMADEV_DEVICE_UD_AV_PORT_ENFORCE },
        { IBV_DEVICE_CURR_QP_STATE_MOD, RDMADEV_DEVICE_CURR_QP_STATE_MOD },
        { IBV_DEVICE_SHUTDOWN_PORT, RDMADEV_DEVICE_SHUTDOWN_PORT },
        { IBV_DEVICE_PORT_ACTIVE_EVENT, RDMADEV_DEVICE_PORT_ACTIVE_EVENT },
        { IBV_DEVICE_SYS_IMAGE_GUID, RDMADEV_DEVICE_SYS_IMAGE_GUID },
        { IBV_DEVICE_RC_RNR_NAK_GEN, RDMADEV_DEVICE_RC_RNR_NAK_GEN },
        { IBV_DEVICE_SRQ_RESIZE, RDMADEV_DEVICE_SRQ_RESIZE },
        { IBV_DEVICE_N_NOTIFY_CQ, RDMADEV_DEVICE_N_NOTIFY_CQ },
        { IBV_DEVICE_MEM_WINDOW, RDMADEV_DEVICE_MEM_WINDOW },
        { IBV_DEVICE_UD_IP_CSUM, RDMADEV_DEVICE_UD_IP_CSUM },
        { IBV_DEVICE_XRC, RDMADEV_DEVICE_XRC },
        { IBV_DEVICE_MEM_MGT_EXTENSIONS, RDMADEV_DEVICE_MEM_MGT_EXTENSIONS },
        { IBV_DEVICE_MEM_WINDOW_TYPE_2A, RDMADEV_DEVICE_MEM_WINDOW_TYPE_2A },
        { IBV_DEVICE_MEM_WINDOW_TYPE_2B, RDMADEV_DEVICE_MEM_WINDOW_TYPE_2B },
        { IBV_DEVICE_RC_IP_CSUM, RDMADEV_DEVICE_RC_IP_CSUM },
        { IBV_DEVICE_RAW_IP_CSUM, RDMADEV_DEVICE_RAW_IP_CSUM },
        { IBV_DEVICE_MANAGED_FLOW_STEERING, RDMADEV_DEVICE_MANAGED_FLOW_STEERING },
    };

    return rdmadev_get_flags(caps, devcap_tbls);
}

static inline RdmaAtomicCap ibdev_atomic_cap(enum ibv_atomic_cap cap)
{
    static RdmadevFlags cap_tbls[] = {
        { IBV_ATOMIC_NONE, RDMADEV_ATOMIC_CAP_NONE },
        { IBV_ATOMIC_HCA, RDMADEV_ATOMIC_CAP_HCA },
        { IBV_ATOMIC_GLOB, RDMADEV_ATOMIC_CAP_GLOB }
    };

    return rdmadev_convert_type(cap, cap_tbls, RDMADEV_ATOMIC_CAP_NONE);
}

static inline RdmaPortCap ibdev_port_cap_to(uint32_t cap)
{
    static RdmadevFlags port_cap_tbls[] = {
        { IBV_PORT_SM, RDMADEV_PORT_SM },
        { IBV_PORT_NOTICE_SUP, RDMADEV_PORT_NOTICE_SUP },
        { IBV_PORT_TRAP_SUP, RDMADEV_PORT_TRAP_SUP },
        { IBV_PORT_OPT_IPD_SUP, RDMADEV_PORT_OPT_IPD_SUP },
        { IBV_PORT_AUTO_MIGR_SUP, RDMADEV_PORT_AUTO_MIGR_SUP },
        { IBV_PORT_SL_MAP_SUP, RDMADEV_PORT_SL_MAP_SUP },
        { IBV_PORT_MKEY_NVRAM, RDMADEV_PORT_MKEY_NVRAM },
        { IBV_PORT_PKEY_NVRAM, RDMADEV_PORT_PKEY_NVRAM },
        { IBV_PORT_LED_INFO_SUP, RDMADEV_PORT_LED_INFO_SUP },
        /* RDMADEV_PORT_SM_DISABLED */
        { IBV_PORT_SYS_IMAGE_GUID_SUP, RDMADEV_PORT_SYS_IMAGE_GUID_SUP },
        { IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP, RDMADEV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP },
        { IBV_PORT_EXTENDED_SPEEDS_SUP, RDMADEV_PORT_EXTENDED_SPEEDS_SUP },
        { IBV_PORT_CAP_MASK2_SUP, RDMADEV_PORT_CAP_MASK2_SUP },
        { IBV_PORT_CM_SUP, RDMADEV_PORT_CM_SUP },
        { IBV_PORT_SNMP_TUNNEL_SUP, RDMADEV_PORT_SNMP_TUNNEL_SUP },
        { IBV_PORT_REINIT_SUP, RDMADEV_PORT_REINIT_SUP },
        { IBV_PORT_DEVICE_MGMT_SUP, RDMADEV_PORT_DEVICE_MGMT_SUP },
        { IBV_PORT_VENDOR_CLASS_SUP, RDMADEV_PORT_VENDOR_CLASS_SUP },
        { IBV_PORT_DR_NOTICE_SUP, RDMADEV_PORT_DR_NOTICE_SUP },
        { IBV_PORT_CAP_MASK_NOTICE_SUP, RDMADEV_PORT_CAP_MASK_NOTICE_SUP },
        { IBV_PORT_BOOT_MGMT_SUP, RDMADEV_PORT_BOOT_MGMT_SUP },
        { IBV_PORT_LINK_LATENCY_SUP, RDMADEV_PORT_LINK_LATENCY_SUP },
        { IBV_PORT_CLIENT_REG_SUP, RDMADEV_PORT_CLIENT_REG_SUP },
        { IBV_PORT_IP_BASED_GIDS, RDMADEV_PORT_IP_BASED_GIDS },
        /* RDMADEV_PORT_LINK_SPEED_WIDTH_TABLE_SUP */
        /* RDMADEV_PORT_VENDOR_SPECIFIC_MADS_TABLE_SUP */
        /* RDMADEV_PORT_MCAST_PKEY_TRAP_SUPPRESSION_SUP */
        /* RDMADEV_PORT_MCAST_FDB_TOP_SUP */
        /* RDMADEV_PORT_HIERARCHY_INFO_SUP */
    };

    return rdmadev_get_flags(cap, port_cap_tbls);
}

static inline RdmadevWcStatus ibdev_wc_status_to(enum ibv_wc_status status)
{
    static RdmadevFlags status_tbls[] = {
        { IBV_WC_SUCCESS, RDMADEV_WC_SUCCESS },
        { IBV_WC_LOC_LEN_ERR, RDMADEV_WC_LOC_LEN_ERR },
        { IBV_WC_LOC_QP_OP_ERR, RDMADEV_WC_LOC_QP_OP_ERR },
        { IBV_WC_LOC_EEC_OP_ERR, RDMADEV_WC_LOC_EEC_OP_ERR },
        { IBV_WC_LOC_PROT_ERR, RDMADEV_WC_LOC_PROT_ERR },
        { IBV_WC_WR_FLUSH_ERR, RDMADEV_WC_WR_FLUSH_ERR },
        { IBV_WC_MW_BIND_ERR, RDMADEV_WC_MW_BIND_ERR },
        { IBV_WC_BAD_RESP_ERR, RDMADEV_WC_BAD_RESP_ERR },
        { IBV_WC_LOC_ACCESS_ERR, RDMADEV_WC_LOC_ACCESS_ERR },
        { IBV_WC_REM_INV_REQ_ERR, RDMADEV_WC_REM_INV_REQ_ERR },
        { IBV_WC_REM_ACCESS_ERR, RDMADEV_WC_REM_ACCESS_ERR },
        { IBV_WC_REM_OP_ERR, RDMADEV_WC_REM_OP_ERR },
        { IBV_WC_RETRY_EXC_ERR, RDMADEV_WC_RETRY_EXC_ERR },
        { IBV_WC_RNR_RETRY_EXC_ERR, RDMADEV_WC_RNR_RETRY_EXC_ERR },
        { IBV_WC_LOC_RDD_VIOL_ERR, RDMADEV_WC_LOC_RDD_VIOL_ERR },
        { IBV_WC_REM_INV_RD_REQ_ERR, RDMADEV_WC_REM_INV_RD_REQ_ERR },
        { IBV_WC_REM_ABORT_ERR, RDMADEV_WC_REM_ABORT_ERR },
        { IBV_WC_INV_EECN_ERR, RDMADEV_WC_INV_EECN_ERR },
        { IBV_WC_INV_EEC_STATE_ERR, RDMADEV_WC_INV_EEC_STATE_ERR },
        { IBV_WC_FATAL_ERR, RDMADEV_WC_FATAL_ERR },
        { IBV_WC_RESP_TIMEOUT_ERR, RDMADEV_WC_RESP_TIMEOUT_ERR },
        { IBV_WC_GENERAL_ERR, RDMADEV_WC_GENERAL_ERR }
    };
    uint64_t _status;

    _status = rdmadev_convert_type(status, status_tbls, RDMADEV_WC_STATUS_MAX);
    if (_status == RDMADEV_WC_STATUS_MAX) {
        ibdev_warn_report("Unknown WC status %d, use general error", status);
        return RDMADEV_WC_GENERAL_ERR;
    }

    return _status;
}

static inline RdmadevWcOpcode ibdev_wc_opcode_to(enum ibv_wc_opcode opcode)
{
    static RdmadevFlags opcode_tbls[] = {
        { IBV_WC_SEND, RDMADEV_WC_SEND },
        { IBV_WC_RDMA_WRITE, RDMADEV_WC_RDMA_WRITE },
        { IBV_WC_RDMA_READ, RDMADEV_WC_RDMA_READ },
        { IBV_WC_COMP_SWAP, RDMADEV_WC_COMP_SWAP },
        { IBV_WC_FETCH_ADD, RDMADEV_WC_FETCH_ADD },
        { IBV_WC_BIND_MW, RDMADEV_WC_BIND_MW },
        { IBV_WC_LOCAL_INV, RDMADEV_WC_LOCAL_INV },
        { IBV_WC_TSO, RDMADEV_WC_OPCODE_MAX }, /* Not support */
        /* { IBV_WC_FLUSH, RDMADEV_WC_FLUSH }, need higher rdma-core */
        { IBV_WC_RECV, RDMADEV_WC_RECV },
        { IBV_WC_RECV_RDMA_WITH_IMM, RDMADEV_WC_RECV_RDMA_WITH_IMM }
    };
    uint64_t _opcode;

    _opcode = rdmadev_convert_type(opcode, opcode_tbls, RDMADEV_WC_OPCODE_MAX);
    assert(_opcode < RDMADEV_WC_OPCODE_MAX);

    return _opcode;
}

static inline uint32_t ibdev_wc_flags_to(uint32_t wc_flags)
{
    static struct RdmadevFlags wc_flags_tbls[] = {
        { IBV_WC_GRH, RDMADEV_WC_GRH },
        { IBV_WC_WITH_IMM, RDMADEV_WC_WITH_IMM },
        { IBV_WC_WITH_INV, RDMADEV_WC_WITH_INVALIDATE },
        { IBV_WC_IP_CSUM_OK, RDMADEV_WC_IP_CSUM_OK }
    };

    return rdmadev_get_flags(wc_flags, wc_flags_tbls);
}

static inline enum ibv_mtu ibdev_mtu(RdmaMtuType mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { RDMADEV_MTU_TYPE_256, IBV_MTU_256},
        { RDMADEV_MTU_TYPE_512, IBV_MTU_512},
        { RDMADEV_MTU_TYPE_1024, IBV_MTU_1024 },
        { RDMADEV_MTU_TYPE_2048, IBV_MTU_2048 },
        { RDMADEV_MTU_TYPE_4096, IBV_MTU_4096 }
    };

    return rdmadev_convert_type(mtu, mtu_tbls, RDMADEV_MTU_TYPE__MAX);
}

static inline RdmaMtuType ibdev_mtu_to(enum ibv_mtu mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { IBV_MTU_256, RDMADEV_MTU_TYPE_256 },
        { IBV_MTU_512, RDMADEV_MTU_TYPE_512 },
        { IBV_MTU_1024, RDMADEV_MTU_TYPE_1024 },
        { IBV_MTU_2048, RDMADEV_MTU_TYPE_2048 },
        { IBV_MTU_4096, RDMADEV_MTU_TYPE_4096 }
    };
    uint64_t _mtu;

    _mtu = rdmadev_convert_type(mtu, mtu_tbls, RDMADEV_MTU_TYPE__MAX);
    if (_mtu == RDMADEV_MTU_TYPE__MAX) {
        ibdev_warn_report("Unknown MTU %d, use 1024", mtu);
        return RDMADEV_MTU_TYPE_1024;
    }

    return _mtu;
}

static inline enum ibv_mig_state ibv_mig_state(RdmadevMigState mig_state)
{
    static RdmadevFlags mig_state_tbls[] = {
        { RDMADEV_MIG_MIGRATED, IBV_MIG_MIGRATED },
        { RDMADEV_MIG_REARM, IBV_MIG_REARM },
        { RDMADEV_MIG_ARMED, IBV_MIG_ARMED }
    };

    return rdmadev_convert_type(mig_state, mig_state_tbls, RDMADEV_MIG_MAX);
}

static inline RdmadevMigState ibv_mig_state_to(enum ibv_mig_state mig_state)
{
    static RdmadevFlags mig_state_tbls[] = {
        { IBV_MIG_MIGRATED, RDMADEV_MIG_MIGRATED },
        { IBV_MIG_REARM, RDMADEV_MIG_REARM },
        { IBV_MIG_ARMED, RDMADEV_MIG_ARMED }
    };

    return rdmadev_convert_type(mig_state, mig_state_tbls, RDMADEV_MIG_MAX);
}

static inline RdmaSpeed ibdev_speed_to(uint32_t speed)
{
    static RdmadevFlags speed_tbls[] = {
        { 2, RDMADEV_SPEED_5GBPS },
        { 4, RDMADEV_SPEED_10GBPS },
        { 8, RDMADEV_SPEED_10GBPS },
        { 32, RDMADEV_SPEED_25GBPS },
        { 64, RDMADEV_SPEED_50GBPS },
        { 128, RDMADEV_SPEED_100GBPS },
        { 256, RDMADEV_SPEED_200GBPS }
    };
    uint64_t _speed;

    _speed = rdmadev_convert_type(speed, speed_tbls, RDMADEV_SPEED__MAX);
    if (_speed == RDMADEV_SPEED__MAX) {
        ibdev_warn_report("Unknown speed %d, use 10Gbps", speed);
        return RDMADEV_SPEED_10GBPS;
    }

    return _speed;
}

static inline RdmaLinkLayer ibdev_link_layer_to(uint8_t link_layer)
{
    static RdmadevFlags link_layer_tbls[] = {
        { IBV_LINK_LAYER_INFINIBAND, RDMADEV_LINK_LAYER_INFINIBAND },
        { IBV_LINK_LAYER_ETHERNET, RDMADEV_LINK_LAYER_ETHERNET }
    };
    uint64_t _link_layer;

    _link_layer = rdmadev_convert_type(link_layer, link_layer_tbls, RDMADEV_LINK_LAYER__MAX);
    if (_link_layer == RDMADEV_LINK_LAYER__MAX) {
        ibdev_warn_report("Unknown link layer %d, use infiniband", link_layer);
        return RDMADEV_LINK_LAYER_INFINIBAND;
    }

    return _link_layer;
}

static inline uint32_t ibdev_access_flags(uint32_t access)
{
    static struct RdmadevFlags mr_access_tbls[] = {
        { RDMADEV_ACCESS_LOCAL_WRITE, IBV_ACCESS_LOCAL_WRITE },
        { RDMADEV_ACCESS_REMOTE_WRITE, IBV_ACCESS_REMOTE_WRITE },
        { RDMADEV_ACCESS_REMOTE_READ, IBV_ACCESS_REMOTE_READ },
        { RDMADEV_ACCESS_REMOTE_ATOMIC, IBV_ACCESS_REMOTE_ATOMIC },
        { RDMADEV_ACCESS_MW_BIND, IBV_ACCESS_MW_BIND }
    };

    return rdmadev_get_flags(access, mr_access_tbls);
}

static inline uint32_t ibdev_qp_attr_mask(uint32_t mask)
{
    static struct RdmadevFlags qp_attr_mask_tbls[] = {
        { RDMADEV_QP_STATE, IBV_QP_STATE },
        { RDMADEV_QP_CUR_STATE, IBV_QP_CUR_STATE },
        { RDMADEV_QP_EN_SQD_ASYNC_NOTIFY, IBV_QP_EN_SQD_ASYNC_NOTIFY },
        { RDMADEV_QP_ACCESS_FLAGS, IBV_QP_ACCESS_FLAGS },
        { RDMADEV_QP_PKEY_INDEX, IBV_QP_PKEY_INDEX },
        { RDMADEV_QP_PORT, IBV_QP_PORT },
        { RDMADEV_QP_QKEY, IBV_QP_QKEY },
        { RDMADEV_QP_AV, IBV_QP_AV },
        { RDMADEV_QP_PATH_MTU, IBV_QP_PATH_MTU },
        { RDMADEV_QP_TIMEOUT, IBV_QP_TIMEOUT },
        { RDMADEV_QP_RETRY_CNT, IBV_QP_RETRY_CNT },
        { RDMADEV_QP_RNR_RETRY, IBV_QP_RNR_RETRY },
        { RDMADEV_QP_RQ_PSN, IBV_QP_RQ_PSN },
        { RDMADEV_QP_MAX_QP_RD_ATOMIC, IBV_QP_MAX_QP_RD_ATOMIC },
        { RDMADEV_QP_ALT_PATH, IBV_QP_ALT_PATH },
        { RDMADEV_QP_MIN_RNR_TIMER, IBV_QP_MIN_RNR_TIMER },
        { RDMADEV_QP_SQ_PSN, IBV_QP_SQ_PSN },
        { RDMADEV_QP_MAX_DEST_RD_ATOMIC, IBV_QP_MAX_DEST_RD_ATOMIC },
        { RDMADEV_QP_PATH_MIG_STATE, IBV_QP_PATH_MIG_STATE },
        { RDMADEV_QP_CAP, IBV_QP_CAP },
        { RDMADEV_QP_DEST_QPN, IBV_QP_DEST_QPN },
        { RDMADEV_QP_RATE_LIMIT, IBV_QP_RATE_LIMIT }
    };

    return rdmadev_get_flags(mask, qp_attr_mask_tbls);
}

static inline enum ibv_qp_state ibv_qp_state(RdmadevQpState state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { RDMADEV_QPS_RESET, IBV_QPS_RESET },
        { RDMADEV_QPS_INIT, IBV_QPS_INIT },
        { RDMADEV_QPS_RTR, IBV_QPS_RTR },
        { RDMADEV_QPS_RTS, IBV_QPS_RTS },
        { RDMADEV_QPS_SQD, IBV_QPS_SQD },
        { RDMADEV_QPS_SQE, IBV_QPS_SQE },
        { RDMADEV_QPS_ERR, IBV_QPS_ERR }
    };

    return rdmadev_convert_type(state, qp_state_tbls, IBV_QPS_UNKNOWN);
}

static inline RdmadevQpState ibv_qp_state_to(enum ibv_qp_state state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { IBV_QPS_RESET, RDMADEV_QPS_RESET },
        { IBV_QPS_INIT, RDMADEV_QPS_INIT },
        { IBV_QPS_RTR, RDMADEV_QPS_RTR },
        { IBV_QPS_RTS, RDMADEV_QPS_RTS },
        { IBV_QPS_SQD, RDMADEV_QPS_SQD },
        { IBV_QPS_SQE, RDMADEV_QPS_SQE },
        { IBV_QPS_ERR, RDMADEV_QPS_ERR }
    };

    return rdmadev_convert_type(state, qp_state_tbls, RDMADEV_QPS_MAX);
}

static inline uint32_t ibdev_srq_attr_mask(uint32_t mask)
{
    static struct RdmadevFlags srq_attr_mask_tbls[] = {
        { RDMADEV_SRQ_MAX_WR, IBV_SRQ_MAX_WR },
        { RDMADEV_SRQ_LIMIT, IBV_SRQ_LIMIT },
    };

    return rdmadev_get_flags(mask, srq_attr_mask_tbls);
}

#define IBV_WR_OPCODE_UNKNOWN 0xFFFFFFFF
static inline enum ibv_wr_opcode ibv_wr_opcode(RdmadevWrOpcode opcode)
{
    static RdmadevFlags wr_opcode_tbls[] = {
        { RDMADEV_WR_RDMA_WRITE, IBV_WR_RDMA_WRITE },
        { RDMADEV_WR_RDMA_WRITE_WITH_IMM, IBV_WR_RDMA_WRITE_WITH_IMM },
        { RDMADEV_WR_SEND, IBV_WR_SEND },
        { RDMADEV_WR_SEND_WITH_IMM, IBV_WR_SEND_WITH_IMM },
        { RDMADEV_WR_SEND_WITH_INV, IBV_WR_SEND_WITH_INV },
        { RDMADEV_WR_RDMA_READ, IBV_WR_RDMA_READ },
        { RDMADEV_WR_RDMA_READ_WITH_INV,  IBV_WR_OPCODE_UNKNOWN},
        { RDMADEV_WR_ATOMIC_CMP_AND_SWP, IBV_WR_ATOMIC_CMP_AND_SWP },
        { RDMADEV_WR_ATOMIC_FETCH_AND_ADD, IBV_WR_ATOMIC_FETCH_AND_ADD },
        { RDMADEV_WR_ATOMIC_WRITE, IBV_WR_OPCODE_UNKNOWN },
        { RDMADEV_WR_MASKED_ATOMIC_CMP_AND_SWP, IBV_WR_OPCODE_UNKNOWN },
        { RDMADEV_WR_MASKED_ATOMIC_FETCH_AND_ADD, IBV_WR_OPCODE_UNKNOWN },
        { RDMADEV_WR_LSO, IBV_WR_OPCODE_UNKNOWN },
        { RDMADEV_WR_LOCAL_INV, IBV_WR_LOCAL_INV },
        { RDMADEV_WR_REG_MR, IBV_WR_OPCODE_UNKNOWN },
        { RDMADEV_WR_BIND_MW, IBV_WR_BIND_MW },
        { RDMADEV_WR_FLUSH, IBV_WR_OPCODE_UNKNOWN }
    };

    return rdmadev_convert_type(opcode, wr_opcode_tbls, IBV_WR_OPCODE_UNKNOWN);
}

static uint32_t ibv_send_flags(uint32_t flags)
{
    static struct RdmadevFlags send_flags_tbls[] = {
        { RDMADEV_SEND_FENCE, IBV_SEND_FENCE },
        { RDMADEV_SEND_SIGNALED, IBV_SEND_SIGNALED },
        { RDMADEV_SEND_SOLICITED, IBV_SEND_SOLICITED },
        { RDMADEV_SEND_INLINE, IBV_SEND_INLINE },
        { RDMADEV_SEND_IP_CSUM, IBV_SEND_IP_CSUM }
    };

    return rdmadev_get_flags(flags, send_flags_tbls);
}

#endif
