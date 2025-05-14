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

static inline uint32_t rocedev_access_flags_from(uint32_t access)
{
    static struct RdmadevFlags access_tbls[] = {
        { RDMADEV_ACCESS_LOCAL_WRITE, ROCE_ACCESS_LOCAL_WRITE },
        { RDMADEV_ACCESS_REMOTE_WRITE, ROCE_ACCESS_REMOTE_WRITE },
        { RDMADEV_ACCESS_REMOTE_READ, ROCE_ACCESS_REMOTE_READ },
        { RDMADEV_ACCESS_REMOTE_ATOMIC, ROCE_ACCESS_REMOTE_ATOMIC },
        { RDMADEV_ACCESS_MW_BIND, ROCE_ACCESS_MW_BIND }
    };

    return rdmadev_get_flags(access, access_tbls);
}

static inline uint32_t rocedev_access_flags_to(uint32_t access)
{
    static struct RdmadevFlags access_tbls[] = {
        { ROCE_ACCESS_LOCAL_WRITE, RDMADEV_ACCESS_LOCAL_WRITE},
        { ROCE_ACCESS_REMOTE_WRITE, RDMADEV_ACCESS_REMOTE_WRITE },
        { ROCE_ACCESS_REMOTE_READ, RDMADEV_ACCESS_REMOTE_READ },
        { ROCE_ACCESS_REMOTE_ATOMIC, RDMADEV_ACCESS_REMOTE_ATOMIC },
        { ROCE_ACCESS_MW_BIND, RDMADEV_ACCESS_MW_BIND }
    };

    return rdmadev_get_flags(access, access_tbls);
}

static inline enum roce_mr_type rocedev_mr_type_from(RdmadevMrTypes mr_type)
{
    static RdmadevFlags mr_type_tbls[] = {
        { RDMADEV_MR_MEM, ROCE_MR_MEM },
        { RDMADEV_MR_FRMR, ROCE_MR_FRMR },
        { RDMADEV_MR_DMA, ROCE_MR_DMA }
    };
    roce_mr_type _mr_type;

    _mr_type = rdmadev_convert_type(mr_type, mr_type_tbls, ROCE_MR_MAX);
    assert(_mr_type < ROCE_MR_MAX);

    return _mr_type;
}

static inline enum roce_qp_state rocedev_qp_state_from(RdmadevQpState state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { RDMADEV_QPS_RESET, ROCE_QPS_RESET },
        { RDMADEV_QPS_INIT, ROCE_QPS_INIT },
        { RDMADEV_QPS_RTR, ROCE_QPS_RTR },
        { RDMADEV_QPS_RTS, ROCE_QPS_RTS },
        { RDMADEV_QPS_SQD, ROCE_QPS_SQD },
        { RDMADEV_QPS_SQE, ROCE_QPS_SQE },
        { RDMADEV_QPS_ERR, ROCE_QPS_ERR }
    };
    roce_qp_state _state;

    _state = rdmadev_convert_type(state, qp_state_tbls, ROCE_QPS_MAX);
    assert(_state < ROCE_QPS_MAX);

    return _state;
}

static inline RdmadevQpState rocedev_qp_state_to(roce_qp_state state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { ROCE_QPS_RESET, RDMADEV_QPS_RESET },
        { ROCE_QPS_INIT, RDMADEV_QPS_INIT },
        { ROCE_QPS_RTR, RDMADEV_QPS_RTR },
        { ROCE_QPS_RTS, RDMADEV_QPS_RTS },
        { ROCE_QPS_SQD, RDMADEV_QPS_SQD },
        { ROCE_QPS_SQE, RDMADEV_QPS_SQE },
        { ROCE_QPS_ERR, RDMADEV_QPS_ERR }
    };
    RdmadevQpState _state;

    _state = rdmadev_convert_type(state, qp_state_tbls, RDMADEV_QPS_MAX);
    assert(_state < RDMADEV_QPS_MAX);

    return _state;
}

static inline enum roce_qp_type rocedev_qp_type_from(RdmadevQpType qpt)
{
    static RdmadevFlags qp_type_tbls[] = {
        { RDMADEV_QPT_SMI, ROCE_QPT_SMI },
        { RDMADEV_QPT_GSI, ROCE_QPT_GSI },
        { RDMADEV_QPT_RC, ROCE_QPT_RC },
        { RDMADEV_QPT_UC, ROCE_QPT_UC },
        { RDMADEV_QPT_RD, ROCE_QPT_RD },
        { RDMADEV_QPT_UD, ROCE_QPT_UD }
    };
    roce_qp_type _qpt;

    _qpt = rdmadev_convert_type(qpt, qp_type_tbls, ROCE_QPT_MAX);
    assert(_qpt < ROCE_QPT_MAX);

    return _qpt;
}

static inline RdmadevQpType rocedev_qp_type_to(roce_qp_type qpt)
{
    static RdmadevFlags qp_type_tbls[] = {
        { ROCE_QPT_SMI, RDMADEV_QPT_SMI },
        { ROCE_QPT_GSI, RDMADEV_QPT_GSI },
        { ROCE_QPT_RC, RDMADEV_QPT_RC },
        { ROCE_QPT_UC, RDMADEV_QPT_UC },
        { ROCE_QPT_RD, RDMADEV_QPT_RD },
        { ROCE_QPT_UD, RDMADEV_QPT_UD }
    };
    RdmadevQpType _qpt;

    _qpt = rdmadev_convert_type(qpt, qp_type_tbls, RDMADEV_QPT_MAX);
    assert(_qpt < RDMADEV_QPT_MAX);

    return _qpt;
}

static inline uint32_t rocedev_qp_flags_from(uint32_t flags)
{
    static struct RdmadevFlags qp_flags_tbls[] = {
        { RDMADEV_QP_SIG_ALL, ROCE_QP_SIG_ALL },
        { RDMADEV_QP_SRQ, ROCE_QP_SRQ },
    };

    return rdmadev_get_flags(flags, qp_flags_tbls);
}

static inline uint32_t rocedev_mtu_from(RdmaMtuType mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { RDMADEV_MTU_TYPE_256, 256},
        { RDMADEV_MTU_TYPE_512, 512},
        { RDMADEV_MTU_TYPE_1024, 1024 },
        { RDMADEV_MTU_TYPE_2048, 2048 },
        { RDMADEV_MTU_TYPE_4096, 4096 }
    };
    uint32_t _mtu;

    _mtu = rdmadev_convert_type(mtu, mtu_tbls, 0);
    assert(_mtu);

    return _mtu;
}

static inline RdmaMtuType rocedev_mtu_to(uint32_t mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { 256, RDMADEV_MTU_TYPE_256 },
        { 512, RDMADEV_MTU_TYPE_512 },
        { 1024, RDMADEV_MTU_TYPE_1024 },
        { 2048, RDMADEV_MTU_TYPE_2048 },
        { 4096, RDMADEV_MTU_TYPE_4096 }
    };
    RdmaMtuType _mtu;

    _mtu = rdmadev_convert_type(mtu, mtu_tbls, RDMADEV_MTU_TYPE__MAX);
    assert(_mtu < RDMADEV_MTU_TYPE__MAX);

    return _mtu;
}

static inline uint32_t rocedev_qp_attr_mask_from(uint32_t mask)
{
    static struct RdmadevFlags qp_attr_mask_tbls[] = {
        { RDMADEV_QP_STATE, ROCE_QP_STATE },
        { RDMADEV_QP_CUR_STATE, ROCE_QP_CUR_STATE },
        { RDMADEV_QP_EN_SQD_ASYNC_NOTIFY, ROCE_QP_EN_SQD_ASYNC_NOTIFY },
        { RDMADEV_QP_ACCESS_FLAGS, ROCE_QP_ACCESS_FLAGS },
        { RDMADEV_QP_PKEY_INDEX, ROCE_QP_PKEY_INDEX },
        { RDMADEV_QP_PORT, ROCE_QP_PORT },
        { RDMADEV_QP_QKEY, ROCE_QP_QKEY },
        { RDMADEV_QP_AV, ROCE_QP_AV },
        { RDMADEV_QP_PATH_MTU, ROCE_QP_PATH_MTU },
        { RDMADEV_QP_TIMEOUT, ROCE_QP_TIMEOUT },
        { RDMADEV_QP_RETRY_CNT, ROCE_QP_RETRY_CNT },
        { RDMADEV_QP_RNR_RETRY, ROCE_QP_RNR_RETRY },
        { RDMADEV_QP_RQ_PSN, ROCE_QP_RQ_PSN },
        { RDMADEV_QP_MAX_QP_RD_ATOMIC, ROCE_QP_MAX_QP_RD_ATOMIC },
        { RDMADEV_QP_ALT_PATH, ROCE_QP_ALT_PATH },
        { RDMADEV_QP_MIN_RNR_TIMER, ROCE_QP_MIN_RNR_TIMER },
        { RDMADEV_QP_SQ_PSN, ROCE_QP_SQ_PSN },
        { RDMADEV_QP_MAX_DEST_RD_ATOMIC, ROCE_QP_MAX_DEST_RD_ATOMIC },
        { RDMADEV_QP_PATH_MIG_STATE, ROCE_QP_PATH_MIG_STATE },
        { RDMADEV_QP_CAP, ROCE_QP_CAP },
        { RDMADEV_QP_DEST_QPN, ROCE_QP_DEST_QPN },
    };

    return rdmadev_get_flags(mask, qp_attr_mask_tbls);
}

static inline uint32_t rocedev_send_flags_from(uint32_t flags)
{
    static struct RdmadevFlags send_flags_tbls[] = {
        { RDMADEV_SEND_FENCE, ROCE_SEND_FENCE },
        { RDMADEV_SEND_SIGNALED, ROCE_SEND_SIGNALED },
        { RDMADEV_SEND_SOLICITED, ROCE_SEND_SOLICITED },
        { RDMADEV_SEND_INLINE, ROCE_SEND_INLINE },
        { RDMADEV_SEND_IP_CSUM, ROCE_SEND_IP_CSUM }
    };

    return rdmadev_get_flags(flags, send_flags_tbls);
}

static inline enum roce_wr_opcode rocedev_wr_opcode(RdmadevWrOpcode opcode)
{
    static RdmadevFlags wr_opcode_tbls[] = {
        { RDMADEV_WR_RDMA_WRITE, ROCE_WR_RDMA_WRITE },
        { RDMADEV_WR_RDMA_WRITE_WITH_IMM, ROCE_WR_RDMA_WRITE_WITH_IMM },
        { RDMADEV_WR_SEND, ROCE_WR_SEND },
        { RDMADEV_WR_SEND_WITH_IMM, ROCE_WR_SEND_WITH_IMM },
        { RDMADEV_WR_SEND_WITH_INV, ROCE_WR_SEND_WITH_INV },
        { RDMADEV_WR_RDMA_READ, ROCE_WR_RDMA_READ },
        { RDMADEV_WR_RDMA_READ_WITH_INV, ROCE_WR_RDMA_READ_WITH_INV},
        { RDMADEV_WR_ATOMIC_CMP_AND_SWP, ROCE_WR_ATOMIC_CMP_AND_SWP },
        { RDMADEV_WR_ATOMIC_FETCH_AND_ADD, ROCE_WR_ATOMIC_FETCH_AND_ADD },
        { RDMADEV_WR_ATOMIC_WRITE, ROCE_WR_ATOMIC_WRITE },
        { RDMADEV_WR_MASKED_ATOMIC_CMP_AND_SWP, ROCE_WR_ATOMIC_CMP_AND_SWP },
        { RDMADEV_WR_MASKED_ATOMIC_FETCH_AND_ADD, ROCE_WR_ATOMIC_FETCH_AND_ADD },
        { RDMADEV_WR_LOCAL_INV, ROCE_WR_LOCAL_INV },
        { RDMADEV_WR_REG_MR, ROCE_WR_REG_MR },
        { RDMADEV_WR_BIND_MW, ROCE_WR_BIND_MW },
        { RDMADEV_WR_FLUSH, ROCE_WR_FLUSH }
    };
    roce_wr_opcode _opcode;

    _opcode = rdmadev_convert_type(opcode, wr_opcode_tbls, ROCE_WR_OPCODE_MAX);
    assert(_opcode < ROCE_WR_OPCODE_MAX);

    return _opcode;
}

static inline uint32_t rocedev_port_cap_to(uint32_t cap)
{
    static RdmadevFlags port_cap_tbls[] = {
        { ROCE_PORT_SM, RDMADEV_PORT_SM },
        { ROCE_PORT_NOTICE_SUP, RDMADEV_PORT_NOTICE_SUP },
        { ROCE_PORT_TRAP_SUP, RDMADEV_PORT_TRAP_SUP },
        { ROCE_PORT_OPT_IPD_SUP, RDMADEV_PORT_OPT_IPD_SUP },
        { ROCE_PORT_AUTO_MIGR_SUP, RDMADEV_PORT_AUTO_MIGR_SUP },
        { ROCE_PORT_SL_MAP_SUP, RDMADEV_PORT_SL_MAP_SUP },
        { ROCE_PORT_MKEY_NVRAM, RDMADEV_PORT_MKEY_NVRAM },
        { ROCE_PORT_PKEY_NVRAM, RDMADEV_PORT_PKEY_NVRAM },
        { ROCE_PORT_LED_INFO_SUP, RDMADEV_PORT_LED_INFO_SUP },
        /* RDMADEV_PORT_SM_DISABLED */
        { ROCE_PORT_SYS_IMAGE_GUID_SUP, RDMADEV_PORT_SYS_IMAGE_GUID_SUP },
        { ROCE_PORT_PKEY_SW_EXT_PORT_TRAP_SUP, RDMADEV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP },
        { ROCE_PORT_EXTENDED_SPEEDS_SUP, RDMADEV_PORT_EXTENDED_SPEEDS_SUP },
        { ROCE_PORT_CAP_MASK2_SUP, RDMADEV_PORT_CAP_MASK2_SUP },
        { ROCE_PORT_CM_SUP, RDMADEV_PORT_CM_SUP },
        { ROCE_PORT_SNMP_TUNNEL_SUP, RDMADEV_PORT_SNMP_TUNNEL_SUP },
        { ROCE_PORT_REINIT_SUP, RDMADEV_PORT_REINIT_SUP },
        { ROCE_PORT_DEVICE_MGMT_SUP, RDMADEV_PORT_DEVICE_MGMT_SUP },
        { ROCE_PORT_VENDOR_CLASS_SUP, RDMADEV_PORT_VENDOR_CLASS_SUP },
        { ROCE_PORT_DR_NOTICE_SUP, RDMADEV_PORT_DR_NOTICE_SUP },
        { ROCE_PORT_CAP_MASK_NOTICE_SUP, RDMADEV_PORT_CAP_MASK_NOTICE_SUP },
        { ROCE_PORT_BOOT_MGMT_SUP, RDMADEV_PORT_BOOT_MGMT_SUP },
        { ROCE_PORT_LINK_LATENCY_SUP, RDMADEV_PORT_LINK_LATENCY_SUP },
        { ROCE_PORT_CLIENT_REG_SUP, RDMADEV_PORT_CLIENT_REG_SUP },
        { ROCE_PORT_IP_BASED_GIDS, RDMADEV_PORT_IP_BASED_GIDS },
        /* RDMADEV_PORT_LINK_SPEED_WIDTH_TABLE_SUP */
        /* RDMADEV_PORT_VENDOR_SPECIFIC_MADS_TABLE_SUP */
        /* RDMADEV_PORT_MCAST_PKEY_TRAP_SUPPRESSION_SUP */
        /* RDMADEV_PORT_MCAST_FDB_TOP_SUP */
        /* RDMADEV_PORT_HIERARCHY_INFO_SUP */
    };

    return rdmadev_get_flags(cap, port_cap_tbls);
}

static inline RdmadevWcStatus rocedev_wc_status_to(enum ibv_wc_status status)
{
    static RdmadevFlags status_tbls[] = {
        { ROCE_WC_SUCCESS, RDMADEV_WC_SUCCESS },
        { ROCE_WC_LOC_LEN_ERR, RDMADEV_WC_LOC_LEN_ERR },
        { ROCE_WC_LOC_QP_OP_ERR, RDMADEV_WC_LOC_QP_OP_ERR },
        { ROCE_WC_LOC_EEC_OP_ERR, RDMADEV_WC_LOC_EEC_OP_ERR },
        { ROCE_WC_LOC_PROT_ERR, RDMADEV_WC_LOC_PROT_ERR },
        { ROCE_WC_WR_FLUSH_ERR, RDMADEV_WC_WR_FLUSH_ERR },
        { ROCE_WC_MW_BIND_ERR, RDMADEV_WC_MW_BIND_ERR },
        { ROCE_WC_BAD_RESP_ERR, RDMADEV_WC_BAD_RESP_ERR },
        { ROCE_WC_LOC_ACCESS_ERR, RDMADEV_WC_LOC_ACCESS_ERR },
        { ROCE_WC_REM_INV_REQ_ERR, RDMADEV_WC_REM_INV_REQ_ERR },
        { ROCE_WC_REM_ACCESS_ERR, RDMADEV_WC_REM_ACCESS_ERR },
        { ROCE_WC_REM_OP_ERR, RDMADEV_WC_REM_OP_ERR },
        { ROCE_WC_RETRY_EXC_ERR, RDMADEV_WC_RETRY_EXC_ERR },
        { ROCE_WC_RNR_RETRY_EXC_ERR, RDMADEV_WC_RNR_RETRY_EXC_ERR },
        { ROCE_WC_LOC_RDD_VIOL_ERR, RDMADEV_WC_LOC_RDD_VIOL_ERR },
        { ROCE_WC_REM_INV_RD_REQ_ERR, RDMADEV_WC_REM_INV_RD_REQ_ERR },
        { ROCE_WC_REM_ABORT_ERR, RDMADEV_WC_REM_ABORT_ERR },
        { ROCE_WC_INV_EECN_ERR, RDMADEV_WC_INV_EECN_ERR },
        { ROCE_WC_INV_EEC_STATE_ERR, RDMADEV_WC_INV_EEC_STATE_ERR },
        { ROCE_WC_FATAL_ERR, RDMADEV_WC_FATAL_ERR },
        { ROCE_WC_RESP_TIMEOUT_ERR, RDMADEV_WC_RESP_TIMEOUT_ERR },
        { ROCE_WC_GENERAL_ERR, RDMADEV_WC_GENERAL_ERR }
    };
    RdmadevWcStatus _status;

    _status = rdmadev_convert_type(status, status_tbls, RDMADEV_WC_STATUS_MAX);
    assert(_status < RDMADEV_WC_STATUS_MAX);

    return _status;
}

static inline RdmadevWcOpcode rocedev_wc_opcode_to(enum roce_wc_opcode opcode)
{
    static RdmadevFlags opcode_tbls[] = {
        { ROCE_WC_SEND, RDMADEV_WC_SEND },
        { ROCE_WC_RDMA_WRITE, RDMADEV_WC_RDMA_WRITE },
        { ROCE_WC_RDMA_READ, RDMADEV_WC_RDMA_READ },
        { ROCE_WC_COMP_SWAP, RDMADEV_WC_COMP_SWAP },
        { ROCE_WC_FETCH_ADD, RDMADEV_WC_FETCH_ADD },
        { ROCE_WC_BIND_MW, RDMADEV_WC_BIND_MW },
        { ROCE_WC_LOCAL_INV, RDMADEV_WC_LOCAL_INV },
        { ROCE_WC_FLUSH, RDMADEV_WC_FLUSH },
        { ROCE_WC_RECV, RDMADEV_WC_RECV },
        { ROCE_WC_RECV_RDMA_WITH_IMM, RDMADEV_WC_RECV_RDMA_WITH_IMM }
    };
    uint64_t _opcode;

    _opcode = rdmadev_convert_type(opcode, opcode_tbls, RDMADEV_WC_OPCODE_MAX);
    assert(_opcode < RDMADEV_WC_OPCODE_MAX);

    return _opcode;
}

static inline uint32_t rocedev_wc_flags_to(uint32_t wc_flags)
{
    static struct RdmadevFlags wc_flags_tbls[] = {
        { ROCE_WC_GRH, RDMADEV_WC_GRH },
        { ROCE_WC_WITH_IMM, RDMADEV_WC_WITH_IMM },
        { ROCE_WC_WITH_INVALIDATE, RDMADEV_WC_WITH_INVALIDATE },
        { ROCE_WC_IP_CSUM_OK, RDMADEV_WC_IP_CSUM_OK },
        { ROCE_WC_WITH_SMAC, RDMADEV_WC_WITH_SMAC },
        { ROCE_WC_WITH_VLAN, RDMADEV_WC_WITH_VLAN },
        { ROCE_WC_WITH_NETWORK_HDR_TYPE, RDMADEV_WC_WITH_NETWORK_HDR_TYPE },
    };

    return rdmadev_get_flags(wc_flags, wc_flags_tbls);
}

#if 0
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

static inline uint32_t ibdev_srq_attr_mask(uint32_t mask)
{
    static struct RdmadevFlags srq_attr_mask_tbls[] = {
        { RDMADEV_SRQ_MAX_WR, IBV_SRQ_MAX_WR },
        { RDMADEV_SRQ_LIMIT, IBV_SRQ_LIMIT },
    };

    return rdmadev_get_flags(mask, srq_attr_mask_tbls);
}
#endif

#endif
