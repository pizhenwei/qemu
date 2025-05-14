/*
 * QEMU VMW PVRDMA - Device types convert from/to QEMU rdmadev
 *
 * Copyright (C) 2024 Bytedance
 *
 * Authors:
 *     zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef PVRDMA_PVRDMA_TYPES_H
#define PVRDMA_PVRDMA_TYPES_H

#include "qemu/error-report.h"
#include "rdma/rdma-utils.h"
#include "pvrdma_dev_api.h"
#include "vmw_pvrdma-abi.h"

#define RDMADEV_INVALID_TYPE (-1UL)

/* Convert device cap flags from rdmadev to pvrdma*/
static inline uint32_t pvrdma_device_cap_flags(uint32_t cap)
{
    /* device cap flags are missing from PVRDMA(use linux kernel IB directly) */
    static RdmadevFlags cap_tbls[] = {
        { RDMADEV_DEVICE_RESIZE_MAX_WR, 1 << 0 },
        { RDMADEV_DEVICE_BAD_PKEY_CNTR, 1 << 1 },
        { RDMADEV_DEVICE_BAD_QKEY_CNTR, 1 << 2 },
        { RDMADEV_DEVICE_RAW_MULTI, 1 << 3 },
        { RDMADEV_DEVICE_AUTO_PATH_MIG, 1 << 4 },
        { RDMADEV_DEVICE_CHANGE_PHY_PORT, 1 << 5 },
        { RDMADEV_DEVICE_UD_AV_PORT_ENFORCE, 1 << 6 },
        { RDMADEV_DEVICE_CURR_QP_STATE_MOD, 1 << 7 },
        { RDMADEV_DEVICE_SHUTDOWN_PORT, 1 << 8 },
        { RDMADEV_DEVICE_PORT_ACTIVE_EVENT, 1 << 10 },
        { RDMADEV_DEVICE_SYS_IMAGE_GUID, 1 << 11 },
        { RDMADEV_DEVICE_RC_RNR_NAK_GEN, 1 << 12 },
        { RDMADEV_DEVICE_SRQ_RESIZE, 1 << 13 },
        { RDMADEV_DEVICE_N_NOTIFY_CQ, 1 << 14 },
        { RDMADEV_DEVICE_MEM_WINDOW, 1 << 17 },
        { RDMADEV_DEVICE_UD_IP_CSUM, 1 << 18 },
        { RDMADEV_DEVICE_XRC, 1 << 20 },
        { RDMADEV_DEVICE_MEM_MGT_EXTENSIONS, 1 << 21 },
        { RDMADEV_DEVICE_MEM_WINDOW_TYPE_2A, 1 << 23 },
        { RDMADEV_DEVICE_MEM_WINDOW_TYPE_2B, 1 << 24 },
        { RDMADEV_DEVICE_RC_IP_CSUM, 1 << 25 },
        { RDMADEV_DEVICE_RAW_IP_CSUM, 1 << 26 },
        { RDMADEV_DEVICE_MANAGED_FLOW_STEERING, 1 << 29 }
    };

    return rdmadev_get_flags(cap, cap_tbls);
}

/* Convert port cap flags from rdmadev to pvrdma */
static inline uint32_t pvrdma_port_cap_flags(uint32_t cap)
{
    /* device cap flags are missing from PVRDMA(use linux kernel IB directly) */
    static RdmadevFlags cap_tbls[] = {
        { RDMADEV_PORT_SM, PVRDMA_PORT_SM },
        { RDMADEV_PORT_NOTICE_SUP, PVRDMA_PORT_NOTICE_SUP },
        { RDMADEV_PORT_TRAP_SUP, PVRDMA_PORT_TRAP_SUP },
        { RDMADEV_PORT_OPT_IPD_SUP, PVRDMA_PORT_OPT_IPD_SUP },
        { RDMADEV_PORT_AUTO_MIGR_SUP, PVRDMA_PORT_AUTO_MIGR_SUP },
        { RDMADEV_PORT_SL_MAP_SUP, PVRDMA_PORT_SL_MAP_SUP },
        { RDMADEV_PORT_MKEY_NVRAM, PVRDMA_PORT_MKEY_NVRAM },
        { RDMADEV_PORT_PKEY_NVRAM, PVRDMA_PORT_PKEY_NVRAM },
        { RDMADEV_PORT_LED_INFO_SUP, PVRDMA_PORT_LED_INFO_SUP },
        { RDMADEV_PORT_SM_DISABLED, PVRDMA_PORT_SM_DISABLED },
        { RDMADEV_PORT_SYS_IMAGE_GUID_SUP, PVRDMA_PORT_SYS_IMAGE_GUID_SUP },
        { RDMADEV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP, PVRDMA_PORT_PKEY_SW_EXT_PORT_TRAP_SUP },
        { RDMADEV_PORT_EXTENDED_SPEEDS_SUP, PVRDMA_PORT_EXTENDED_SPEEDS_SUP },
        { RDMADEV_PORT_CM_SUP, PVRDMA_PORT_CM_SUP },
        { RDMADEV_PORT_SNMP_TUNNEL_SUP, PVRDMA_PORT_SNMP_TUNNEL_SUP },
        { RDMADEV_PORT_REINIT_SUP, PVRDMA_PORT_REINIT_SUP },
        { RDMADEV_PORT_DEVICE_MGMT_SUP, PVRDMA_PORT_DEVICE_MGMT_SUP },
        { RDMADEV_PORT_VENDOR_CLASS_SUP, PVRDMA_PORT_VENDOR_CLASS_SUP },
        { RDMADEV_PORT_DR_NOTICE_SUP, PVRDMA_PORT_DR_NOTICE_SUP },
        { RDMADEV_PORT_CAP_MASK_NOTICE_SUP, PVRDMA_PORT_CAP_MASK_NOTICE_SUP },
        { RDMADEV_PORT_BOOT_MGMT_SUP, PVRDMA_PORT_BOOT_MGMT_SUP },
        { RDMADEV_PORT_LINK_LATENCY_SUP, PVRDMA_PORT_LINK_LATENCY_SUP },
        { RDMADEV_PORT_CLIENT_REG_SUP, PVRDMA_PORT_CLIENT_REG_SUP },
        { RDMADEV_PORT_IP_BASED_GIDS, PVRDMA_PORT_IP_BASED_GIDS }
    };

    return rdmadev_get_flags(cap, cap_tbls);
}

/* Convert MTU from rdmadev to pvrdma */
static inline enum pvrdma_mtu pvrdma_mtu(RdmaMtuType mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { RDMADEV_MTU_TYPE_256, PVRDMA_MTU_256 },
        { RDMADEV_MTU_TYPE_512, PVRDMA_MTU_512 },
        { RDMADEV_MTU_TYPE_1024, PVRDMA_MTU_1024 },
        { RDMADEV_MTU_TYPE_2048, PVRDMA_MTU_2048 },
        { RDMADEV_MTU_TYPE_4096, PVRDMA_MTU_4096 }
    };
    uint64_t _mtu;

    _mtu = rdmadev_convert_type(mtu, mtu_tbls, 0);
    if (_mtu == 0) {
        pvrdma_warn_report("Unknown MTU %d, use 1024", mtu);
        return PVRDMA_MTU_1024;
    }

    return _mtu;
}

/* Convert MTU from pvrdma to rdmadev */
static inline RdmaMtuType pvrdma_mtu_to(enum pvrdma_mtu mtu)
{
    static RdmadevFlags mtu_tbls[] = {
        { PVRDMA_MTU_256, RDMADEV_MTU_TYPE_256 },
        { PVRDMA_MTU_512, RDMADEV_MTU_TYPE_512 },
        { PVRDMA_MTU_1024, RDMADEV_MTU_TYPE_1024 },
        { PVRDMA_MTU_2048, RDMADEV_MTU_TYPE_2048 },
        { PVRDMA_MTU_4096, RDMADEV_MTU_TYPE_4096 }
    };

    return rdmadev_convert_type(mtu, mtu_tbls, RDMADEV_MTU_TYPE__MAX);
}

/* Convert port speed from rdmadev to pvrdma */
static inline enum pvrdma_port_speed pvrdma_speed(RdmaSpeed speed)
{
    static RdmadevFlags speed_tbls[] = {
        { RDMADEV_SPEED_5GBPS, PVRDMA_SPEED_SDR },
        { RDMADEV_SPEED_10GBPS, PVRDMA_SPEED_DDR },
        { RDMADEV_SPEED_25GBPS, PVRDMA_SPEED_QDR },
        { RDMADEV_SPEED_50GBPS, PVRDMA_SPEED_FDR },
        { RDMADEV_SPEED_100GBPS, PVRDMA_SPEED_EDR },
        { RDMADEV_SPEED_200GBPS, PVRDMA_SPEED_EDR } /* FIXME */
    };
    uint64_t _speed;

    _speed = rdmadev_convert_type(speed, speed_tbls, 0);
    if (_speed == 0) {
        pvrdma_warn_report("Unknown speed %d, use DDR", speed);
        return PVRDMA_SPEED_DDR;
    }

    return _speed;
}

/* Convert access flags from pvrdma to rdmadev */
static inline uint32_t pvrdma_access_flags_to(uint32_t access)
{
    static RdmadevFlags access_tbls[] = {
        { PVRDMA_ACCESS_LOCAL_WRITE, RDMADEV_ACCESS_LOCAL_WRITE },
        { PVRDMA_ACCESS_REMOTE_WRITE, RDMADEV_ACCESS_REMOTE_WRITE },
        { PVRDMA_ACCESS_REMOTE_READ, RDMADEV_ACCESS_REMOTE_READ },
        { PVRDMA_ACCESS_REMOTE_ATOMIC, RDMADEV_ACCESS_REMOTE_ATOMIC },
        { PVRDMA_ACCESS_MW_BIND, RDMADEV_ACCESS_MW_BIND }
    };

    return rdmadev_get_flags(access, access_tbls);
}

/* Convert QP type from pvrdma to rdmadev */
static inline RdmadevQpType pvrdma_qp_type_to(enum pvrdma_qp_type qp_type)
{
    static RdmadevFlags qp_type_tbls[] = {
        { PVRDMA_QPT_SMI, RDMADEV_QPT_SMI },
        { PVRDMA_QPT_GSI, RDMADEV_QPT_GSI },
        { PVRDMA_QPT_RC, RDMADEV_QPT_RC },
        { PVRDMA_QPT_UC, RDMADEV_QPT_UC },
        { PVRDMA_QPT_UD, RDMADEV_QPT_UD },
    };
    uint64_t _qp_type;

    _qp_type = rdmadev_convert_type(qp_type, qp_type_tbls, RDMADEV_QPT_MAX);
    if (_qp_type == RDMADEV_QPT_MAX) {
        return RDMADEV_QPT_MAX;
    }

    return _qp_type;
}

/* Convert QP state from rdmadev to pvrdma */
static inline enum pvrdma_qp_state pvrdma_qp_state(RdmadevQpState state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { RDMADEV_QPS_RESET, PVRDMA_QPS_RESET },
        { RDMADEV_QPS_INIT, PVRDMA_QPS_INIT },
        { RDMADEV_QPS_RTR, PVRDMA_QPS_RTR },
        { RDMADEV_QPS_RTS, PVRDMA_QPS_RTS },
        { RDMADEV_QPS_SQD, PVRDMA_QPS_SQD },
        { RDMADEV_QPS_SQE, PVRDMA_QPS_SQE },
        { RDMADEV_QPS_ERR, PVRDMA_QPS_ERR }
    };

    return rdmadev_convert_type(state, qp_state_tbls, RDMADEV_INVALID_TYPE);
}

/* Convert QP state from pvrdma to rdmadev */
static inline RdmadevQpState pvrdma_qp_state_to(enum pvrdma_qp_state state)
{
    static RdmadevFlags qp_state_tbls[] = {
        { PVRDMA_QPS_RESET, RDMADEV_QPS_RESET },
        { PVRDMA_QPS_INIT, RDMADEV_QPS_INIT },
        { PVRDMA_QPS_RTR, RDMADEV_QPS_RTR },
        { PVRDMA_QPS_RTS, RDMADEV_QPS_RTS },
        { PVRDMA_QPS_SQD, RDMADEV_QPS_SQD },
        { PVRDMA_QPS_SQE, RDMADEV_QPS_SQE },
        { PVRDMA_QPS_ERR, RDMADEV_QPS_ERR }
    };

    return rdmadev_convert_type(state, qp_state_tbls, RDMADEV_QPS_MAX);
}

/* Convert QP migrate state from pvrdma to rdmadev */
static inline uint32_t pvrdma_mig_state(RdmadevMigState state)
{
    static RdmadevFlags mig_state_tbls[] = {
        { RDMADEV_MIG_MIGRATED, PVRDMA_MIG_MIGRATED },
        { RDMADEV_MIG_REARM, PVRDMA_MIG_REARM },
        { RDMADEV_MIG_ARMED, PVRDMA_MIG_ARMED }
    };

    return rdmadev_get_flags(state, mig_state_tbls);
}

/* Convert QP migrate state from pvrdma to rdmadev */
static inline uint32_t pvrdma_mig_state_to(enum pvrdma_mig_state state)
{
    static RdmadevFlags mig_state_tbls[] = {
        { PVRDMA_MIG_MIGRATED, RDMADEV_MIG_MIGRATED },
        { PVRDMA_MIG_REARM, RDMADEV_MIG_REARM },
        { PVRDMA_MIG_ARMED, RDMADEV_MIG_ARMED }
    };

    return rdmadev_get_flags(state, mig_state_tbls);
}

/* Convert QP attribute mask from pvrdma to rdmadev */
static inline uint32_t pvrdma_qp_attr_mask_to(uint32_t mask)
{
    static RdmadevFlags qp_attr_tbls[] = {
        { PVRDMA_QP_STATE, RDMADEV_QP_STATE },
        { PVRDMA_QP_CUR_STATE, RDMADEV_QP_CUR_STATE },
        { PVRDMA_QP_EN_SQD_ASYNC_NOTIFY, RDMADEV_QP_EN_SQD_ASYNC_NOTIFY },
        { PVRDMA_QP_ACCESS_FLAGS, RDMADEV_QP_ACCESS_FLAGS },
        { PVRDMA_QP_PKEY_INDEX, RDMADEV_QP_PKEY_INDEX },
        { PVRDMA_QP_PORT, RDMADEV_QP_PORT },
        { PVRDMA_QP_QKEY, RDMADEV_QP_QKEY },
        { PVRDMA_QP_AV, RDMADEV_QP_AV },
        { PVRDMA_QP_PATH_MTU, RDMADEV_QP_PATH_MTU },
        { PVRDMA_QP_TIMEOUT, RDMADEV_QP_TIMEOUT },
        { PVRDMA_QP_RETRY_CNT, RDMADEV_QP_RETRY_CNT },
        { PVRDMA_QP_RNR_RETRY, RDMADEV_QP_RNR_RETRY },
        { PVRDMA_QP_RQ_PSN, RDMADEV_QP_RQ_PSN },
        { PVRDMA_QP_MAX_QP_RD_ATOMIC, RDMADEV_QP_MAX_QP_RD_ATOMIC },
        { PVRDMA_QP_ALT_PATH, RDMADEV_QP_ALT_PATH },
        { PVRDMA_QP_MIN_RNR_TIMER, RDMADEV_QP_MIN_RNR_TIMER },
        { PVRDMA_QP_SQ_PSN, RDMADEV_QP_SQ_PSN },
        { PVRDMA_QP_MAX_DEST_RD_ATOMIC, RDMADEV_QP_MAX_DEST_RD_ATOMIC },
        { PVRDMA_QP_PATH_MIG_STATE, RDMADEV_QP_PATH_MIG_STATE },
        { PVRDMA_QP_CAP, RDMADEV_QP_CAP },
        { PVRDMA_QP_DEST_QPN, RDMADEV_QP_DEST_QPN }
    };

    return rdmadev_get_flags(mask, qp_attr_tbls);
}

/* Convert SRQ attribute mask from pvrdma to rdmadev */
static inline uint32_t pvrdma_srq_attr_mask_to(uint32_t mask)
{
    /* SRQ attribute mask is missing from pvrdma_verbs.h */
    static RdmadevFlags mask_tbls[] = {
        { 1 << 0, RDMADEV_SRQ_MAX_WR },
        { 1 << 1, RDMADEV_SRQ_LIMIT },
    };

    return rdmadev_get_flags(mask, mask_tbls);
}

/* Convert GID type from pvrdma to rdmadev */
static inline RdmaGidType pvrdma_gid_type_to(uint8_t gid_type)
{
    static RdmadevFlags gid_type_tbls[] = {
        { PVRDMA_GID_TYPE_FLAG_ROCE_V1, RDMADEV_GID_TYPE_ROCE_V1 },
        { PVRDMA_GID_TYPE_FLAG_ROCE_V2, RDMADEV_GID_TYPE_ROCE_V2 }
    };

    return rdmadev_convert_type(gid_type, gid_type_tbls, RDMADEV_GID_TYPE__MAX);
}

/* Convert WC status from rdmadev to pvrdma */
static inline enum pvrdma_wc_status pvrdma_wc_status(RdmadevWcStatus status)
{
    static RdmadevFlags status_tbls[] = {
        { RDMADEV_WC_SUCCESS, PVRDMA_WC_SUCCESS },
        { RDMADEV_WC_LOC_LEN_ERR, PVRDMA_WC_LOC_LEN_ERR },
        { RDMADEV_WC_LOC_QP_OP_ERR, PVRDMA_WC_LOC_QP_OP_ERR },
        { RDMADEV_WC_LOC_EEC_OP_ERR, PVRDMA_WC_LOC_EEC_OP_ERR },
        { RDMADEV_WC_LOC_PROT_ERR, PVRDMA_WC_LOC_PROT_ERR },
        { RDMADEV_WC_WR_FLUSH_ERR, PVRDMA_WC_WR_FLUSH_ERR },
        { RDMADEV_WC_MW_BIND_ERR, PVRDMA_WC_MW_BIND_ERR },
        { RDMADEV_WC_BAD_RESP_ERR, PVRDMA_WC_BAD_RESP_ERR },
        { RDMADEV_WC_LOC_ACCESS_ERR, PVRDMA_WC_LOC_ACCESS_ERR },
        { RDMADEV_WC_REM_INV_REQ_ERR, PVRDMA_WC_REM_INV_REQ_ERR },
        { RDMADEV_WC_REM_ACCESS_ERR, PVRDMA_WC_REM_ACCESS_ERR },
        { RDMADEV_WC_REM_OP_ERR, PVRDMA_WC_REM_OP_ERR },
        { RDMADEV_WC_RETRY_EXC_ERR, PVRDMA_WC_RETRY_EXC_ERR },
        { RDMADEV_WC_RNR_RETRY_EXC_ERR, PVRDMA_WC_RNR_RETRY_EXC_ERR },
        { RDMADEV_WC_LOC_RDD_VIOL_ERR, PVRDMA_WC_LOC_RDD_VIOL_ERR },
        { RDMADEV_WC_REM_INV_RD_REQ_ERR, PVRDMA_WC_REM_INV_RD_REQ_ERR },
        { RDMADEV_WC_REM_ABORT_ERR, PVRDMA_WC_REM_ABORT_ERR },
        { RDMADEV_WC_INV_EECN_ERR, PVRDMA_WC_INV_EECN_ERR },
        { RDMADEV_WC_INV_EEC_STATE_ERR, PVRDMA_WC_INV_EEC_STATE_ERR },
        { RDMADEV_WC_FATAL_ERR, PVRDMA_WC_FATAL_ERR },
        { RDMADEV_WC_RESP_TIMEOUT_ERR, PVRDMA_WC_RESP_TIMEOUT_ERR },
        { RDMADEV_WC_GENERAL_ERR, PVRDMA_WC_GENERAL_ERR }
    };
    uint64_t _status;

    _status = rdmadev_convert_type(status, status_tbls, RDMADEV_WC_STATUS_MAX);
    if (_status == RDMADEV_WC_STATUS_MAX) {
        pvrdma_warn_report("Unknown WC status %d, use general error", status);
        return PVRDMA_WC_GENERAL_ERR;
    }

    return _status;
}

/* Convert WC opcode from rdmadev to pvrdma */
static inline enum pvrdma_wc_opcode pvrdma_wc_opcode(RdmadevWcOpcode wc_opcode)
{
    static RdmadevFlags wc_opcode_tbls[] = {
        { RDMADEV_WC_SEND, PVRDMA_WC_SEND },
        { RDMADEV_WC_RDMA_WRITE, PVRDMA_WC_RDMA_WRITE },
        { RDMADEV_WC_RDMA_READ, PVRDMA_WC_RDMA_READ },
        { RDMADEV_WC_COMP_SWAP, PVRDMA_WC_COMP_SWAP },
        { RDMADEV_WC_FETCH_ADD, PVRDMA_WC_FETCH_ADD },
        { RDMADEV_WC_BIND_MW, PVRDMA_WC_BIND_MW },
        { RDMADEV_WC_LOCAL_INV, PVRDMA_WC_LOCAL_INV },
        { RDMADEV_WC_LSO, PVRDMA_WC_LSO },
        /* ATOMIC WRITE is not supported by PVRDMA */
        { RDMADEV_WC_REG_MR, PVRDMA_WC_FAST_REG_MR },
        { RDMADEV_WC_MASKED_COMP_SWAP, PVRDMA_WC_MASKED_COMP_SWAP },
        { RDMADEV_WC_MASKED_FETCH_ADD, PVRDMA_WC_MASKED_FETCH_ADD },
        /* FLUSH is not supported by PVRDMA */
        { RDMADEV_WC_RECV, PVRDMA_WC_RECV},
        { RDMADEV_WC_RECV_RDMA_WITH_IMM, PVRDMA_WC_RECV_RDMA_WITH_IMM },
    };
    uint64_t _wc_opcode;

    _wc_opcode = rdmadev_convert_type(wc_opcode, wc_opcode_tbls, RDMADEV_INVALID_TYPE);
    assert(_wc_opcode != RDMADEV_INVALID_TYPE);

    return _wc_opcode;
}

/* Convert WC flags from rdmadev to pvrdma */
static inline uint32_t pvrdma_wc_flags(uint32_t flags)
{
    static RdmadevFlags wc_flags_tbls[] = {
        { RDMADEV_WC_GRH, PVRDMA_WC_GRH },
        { RDMADEV_WC_WITH_IMM, PVRDMA_WC_WITH_IMM },
        { RDMADEV_WC_WITH_INVALIDATE, PVRDMA_WC_WITH_INVALIDATE },
        { RDMADEV_WC_IP_CSUM_OK, PVRDMA_WC_IP_CSUM_OK },
        { RDMADEV_WC_WITH_SMAC, PVRDMA_WC_WITH_SMAC },
        { RDMADEV_WC_WITH_VLAN, PVRDMA_WC_WITH_VLAN },
        { RDMADEV_WC_WITH_NETWORK_HDR_TYPE, PVRDMA_WC_WITH_NETWORK_HDR_TYPE }
    };

    return rdmadev_get_flags(flags, wc_flags_tbls);
}

/* Convert Send WR flags from pvrdma to rdmadev */
static inline uint32_t pvrdma_send_flags_to(uint32_t flags)
{
    static RdmadevFlags send_flags_tbls[] = {
        { PVRDMA_SEND_FENCE, RDMADEV_SEND_FENCE },
        { PVRDMA_SEND_SIGNALED, RDMADEV_SEND_SIGNALED },
        { PVRDMA_SEND_SOLICITED, RDMADEV_SEND_SOLICITED },
        { PVRDMA_SEND_INLINE, RDMADEV_SEND_INLINE },
        { PVRDMA_SEND_IP_CSUM, RDMADEV_SEND_IP_CSUM }
    };

    return rdmadev_get_flags(flags, send_flags_tbls);
}

/* Convert Send WR opcode from pvrdma to rdmadev */
static inline RdmadevWrOpcode pvrdma_wr_opcode_to(enum pvrdma_wr_opcode opcode)
{
    static RdmadevFlags wr_opcode_tbls[] = {
        { PVRDMA_WR_RDMA_WRITE, RDMADEV_WR_RDMA_WRITE },
        { PVRDMA_WR_RDMA_WRITE_WITH_IMM, RDMADEV_WR_RDMA_WRITE_WITH_IMM },
        { PVRDMA_WR_SEND, RDMADEV_WR_SEND },
        { PVRDMA_WR_SEND_WITH_IMM, RDMADEV_WR_SEND_WITH_IMM },
        { PVRDMA_WR_RDMA_READ, RDMADEV_WR_RDMA_READ },
        { PVRDMA_WR_ATOMIC_CMP_AND_SWP, RDMADEV_WR_ATOMIC_CMP_AND_SWP },
        { PVRDMA_WR_ATOMIC_FETCH_AND_ADD, RDMADEV_WR_ATOMIC_FETCH_AND_ADD },
        { PVRDMA_WR_LSO, RDMADEV_WR_LSO },
        { PVRDMA_WR_SEND_WITH_INV, RDMADEV_WR_SEND_WITH_INV },
        { PVRDMA_WR_RDMA_READ_WITH_INV, RDMADEV_WR_RDMA_READ_WITH_INV },
        { PVRDMA_WR_LOCAL_INV, RDMADEV_WR_LOCAL_INV },
        { PVRDMA_WR_FAST_REG_MR, RDMADEV_WR_REG_MR },
        { PVRDMA_WR_MASKED_ATOMIC_CMP_AND_SWP, RDMADEV_WR_MASKED_ATOMIC_CMP_AND_SWP },
        { PVRDMA_WR_MASKED_ATOMIC_FETCH_AND_ADD, RDMADEV_WR_MASKED_ATOMIC_FETCH_AND_ADD },
        { PVRDMA_WR_BIND_MW, RDMADEV_WR_BIND_MW },
    };

    return rdmadev_convert_type(opcode, wr_opcode_tbls, RDMADEV_WR_OPCODE_MAX);
}

#endif
