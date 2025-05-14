/*
 * QEMU RDMA Backend: Type Definitions
 *
 * Copyright (c) 2024 Bytedance
 *
 * Authors:
 *     zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef RDMA_TYPES_H
#define RDMA_TYPES_H

#include "qemu/queue.h"
#include "qapi/qapi-types-rdma.h"

typedef union RdmadevGid {
    uint8_t raw[16];
    struct {
        __be64 subnet_prefix;
        __be64 interface_id;
    } global;
} RdmadevGid;

typedef struct RdmadevGlobalRoute {
    RdmadevGid dgid;
    uint32_t flow_label;
    uint8_t sgid_index;
    uint8_t hop_limit;
    uint8_t traffic_class;
} RdmadevGlobalRoute;

typedef struct RdmadevAhAttr {
    RdmadevGlobalRoute grh;
    uint16_t dlid;
    uint8_t sl;
    uint8_t src_path_bits;
    uint8_t static_rate;
    uint8_t port_num;
    uint8_t dmac[6];
} RdmadevAhAttr;

typedef enum RdmadevSrqType {
    RDMADEV_SRQT_BASIC,
    /* XXX RDMADEV_SRQT_XRC is to be supported */
    /* the lack of RDMADEV_SRQT_TM because IB SPEC not supports Tag Matching */

    RDMADEV_SRQT_MAX,
} RdmadevSrqType;

typedef enum RdmadevSrqAttrMask {
    RDMADEV_SRQ_MAX_WR = 1 << 0,
    RDMADEV_SRQ_LIMIT  = 1 << 1
} RdmadevSrqAttrMask;

typedef struct RdmadevSrqAttr {
    uint32_t max_wr;
    uint32_t max_sge;
    uint32_t srq_limit;
} RdmadevSrqAttr;

typedef enum RdmadevQpType {
    RDMADEV_QPT_SMI = 0, /* Note: MUST be 0 */
    RDMADEV_QPT_GSI = 1, /* Note: MUST be 1 */
    RDMADEV_QPT_RC,
    RDMADEV_QPT_UC,
    RDMADEV_QPT_RD,
    RDMADEV_QPT_UD,

    RDMADEV_QPT_MAX
} RdmadevQpType;

static inline const char *rdmadev_qp_type_str(RdmadevQpType qp_type)
{
    static const char *qp_types[] =  { "SMI", "GSI", "RC", "UC", "RD", "UD" };

    assert(qp_type < RDMADEV_QPT_MAX);
    return qp_types[qp_type];
}

typedef enum RdmadevQpFlags {
    RDMADEV_QP_SIG_ALL = (1 << 0),
    RDMADEV_QP_SRQ     = (1 << 31),
} RdmadevQpFlags;

typedef enum RdmadevQpState {
    RDMADEV_QPS_RESET,
    RDMADEV_QPS_INIT,
    RDMADEV_QPS_RTR,
    RDMADEV_QPS_RTS,
    RDMADEV_QPS_SQD,
    RDMADEV_QPS_SQE,
    RDMADEV_QPS_ERR,

    RDMADEV_QPS_MAX
} RdmadevQpState;

typedef enum RdmadevMigState {
    RDMADEV_MIG_MIGRATED,
    RDMADEV_MIG_REARM,
    RDMADEV_MIG_ARMED,

    RDMADEV_MIG_MAX,
} RdmadevMigState;

typedef struct RdmadevQpCap {
    uint32_t max_send_wr;
    uint32_t max_recv_wr;
    uint32_t max_send_sge;
    uint32_t max_recv_sge;
    uint32_t max_inline_data;
} RdmadevQpCap;

typedef enum RdmadevQpAttrMask {
    RDMADEV_QP_STATE                     = (1 << 0),
    RDMADEV_QP_CUR_STATE                 = (1 << 1),
    RDMADEV_QP_EN_SQD_ASYNC_NOTIFY       = (1 << 2),
    RDMADEV_QP_ACCESS_FLAGS              = (1 << 3),
    RDMADEV_QP_PKEY_INDEX                = (1 << 4),
    RDMADEV_QP_PORT                      = (1 << 5),
    RDMADEV_QP_QKEY                      = (1 << 6),
    RDMADEV_QP_AV                        = (1 << 7),
    RDMADEV_QP_PATH_MTU                  = (1 << 8),
    RDMADEV_QP_TIMEOUT                   = (1 << 9),
    RDMADEV_QP_RETRY_CNT                 = (1 << 10),
    RDMADEV_QP_RNR_RETRY                 = (1 << 11),
    RDMADEV_QP_RQ_PSN                    = (1 << 12),
    RDMADEV_QP_MAX_QP_RD_ATOMIC          = (1 << 13),
    RDMADEV_QP_ALT_PATH                  = (1 << 14),
    RDMADEV_QP_MIN_RNR_TIMER             = (1 << 15),
    RDMADEV_QP_SQ_PSN                    = (1 << 16),
    RDMADEV_QP_MAX_DEST_RD_ATOMIC        = (1 << 17),
    RDMADEV_QP_PATH_MIG_STATE            = (1 << 18),
    RDMADEV_QP_CAP                       = (1 << 19),
    RDMADEV_QP_DEST_QPN                  = (1 << 20),
    RDMADEV_QP_RATE_LIMIT                = (1 << 21),
    RDMADEV_QP_FLAGS                     = (1 << 31)
} RdmadevQpAttrMask;

typedef struct RdmadevQpAttr {
    RdmadevQpState qp_state;
    RdmadevQpState cur_qp_state;
    RdmadevMigState path_mig_state;
    RdmadevQpCap cap;
    RdmadevAhAttr ah_attr;
    RdmadevAhAttr alt_ah_attr;
    RdmaMtuType path_mtu;
    uint32_t qkey;
    uint32_t rq_psn;
    uint32_t sq_psn;
    uint32_t dest_qp_num;
    uint32_t qp_access_flags;
    uint32_t port_num;
    uint32_t alt_port_num;
    uint32_t rate_limit;
    uint16_t pkey_index;
    uint16_t alt_pkey_index;
    uint8_t en_sqd_async_notify;
    uint8_t max_dest_rd_atomic;
    uint8_t max_rd_atomic;
    uint8_t min_rnr_timer;
    uint8_t retry_cnt;
    uint8_t rnr_retry;
    uint8_t sq_draining;
    uint8_t timeout;
    uint8_t alt_timeout;
    uint32_t flags;
} RdmadevQpAttr;

typedef struct RdmadevSge {
    uint64_t addr;
    uint32_t length;
    uint32_t lkey;
} RdmadevSge;

typedef struct RdmadevRecvWr {
    uint64_t wr_id;
    uint32_t num_sge;
    RdmadevSge sge[];
} RdmadevRecvWr;

static inline uint32_t rdmadev_recv_wr_size(uint32_t max_recv_sge)
{
    return sizeof(RdmadevRecvWr) + sizeof(RdmadevSge) * max_recv_sge;
}

typedef enum RdmadevMrTypes {
    /* Normal memory region. */
    RDMADEV_MR_MEM,
    /* Fast reg memory region. */
    RDMADEV_MR_FRMR,
    /* DMA region. VA=PA */
    RDMADEV_MR_DMA,

    /* Keep last */
    RDMADEV_MR_MAX,
} RdmadevMrTypes;

static inline const char *rdmadev_mr_type(RdmadevMrTypes mr_type)
{
    static const char *mr_types[] =  { "MEM", "FRMR", "DMA" };

    assert(mr_type < RDMADEV_MR_MAX);
    return mr_types[mr_type];
}

typedef enum RdmadevAccessFlags {
    RDMADEV_ACCESS_LOCAL_WRITE   = (1 << 0),
    RDMADEV_ACCESS_REMOTE_WRITE  = (1 << 1),
    RDMADEV_ACCESS_REMOTE_READ   = (1 << 2),
    RDMADEV_ACCESS_REMOTE_ATOMIC = (1 << 3),
    RDMADEV_ACCESS_MW_BIND       = (1 << 4)
} RdmadevAccessFlags;

#define RDMADEV_ACCESS_REMOTE ( RDMADEV_ACCESS_REMOTE_WRITE | \
                                RDMADEV_ACCESS_REMOTE_READ  | \
                                RDMADEV_ACCESS_REMOTE_ATOMIC )

typedef enum RdmadevWrOpcode {
    RDMADEV_WR_RDMA_WRITE,
    RDMADEV_WR_RDMA_WRITE_WITH_IMM,
    RDMADEV_WR_SEND,
    RDMADEV_WR_SEND_WITH_IMM,
    RDMADEV_WR_SEND_WITH_INV,
    RDMADEV_WR_RDMA_READ,
    RDMADEV_WR_RDMA_READ_WITH_INV,
    RDMADEV_WR_ATOMIC_CMP_AND_SWP,
    RDMADEV_WR_ATOMIC_FETCH_AND_ADD,
    RDMADEV_WR_ATOMIC_WRITE,
    RDMADEV_WR_MASKED_ATOMIC_CMP_AND_SWP,
    RDMADEV_WR_MASKED_ATOMIC_FETCH_AND_ADD,
    RDMADEV_WR_LSO,
    RDMADEV_WR_LOCAL_INV,
    RDMADEV_WR_REG_MR,
    RDMADEV_WR_BIND_MW,
    RDMADEV_WR_FLUSH,

    RDMADEV_WR_OPCODE_MAX
} RdmadevWrOpcode;

static inline const char *rdmadev_wr_opcode(RdmadevWrOpcode opcode)
{
    static const char *wr_opcode[] = {
        "RDMA-WRITE",
        "RDMA-WRITE-WITH-IMM",
        "SEND",
        "SEND-WITH-IMM",
        "SEND-WITH-INV",
        "RDMA-READ",
        "RDMA-READ-WITH-INV",
        "ATOMIC-CMP-AND-SWP",
        "ATOMIC-FETCH-AND-ADD",
        "ATOMIC-WRITE",
        "MASKED-ATOMIC-CMP-AND-SWP",
        "MASKED-ATOMIC-FETCH-AND-ADD",
        "LSO",
        "LOCAL-INV",
        "REG-MR",
        "REG-MR-INTEGRITY",
        "BIND-MW",
        "FLUSH" };

    assert(opcode < RDMADEV_WR_OPCODE_MAX);
    return wr_opcode[opcode];
}

typedef enum RdmadevSendFlags {
    RDMADEV_SEND_FENCE          = (1 << 0),
    RDMADEV_SEND_SIGNALED       = (1 << 1),
    RDMADEV_SEND_SOLICITED      = (1 << 2),
    RDMADEV_SEND_INLINE         = (1 << 3),
    RDMADEV_SEND_IP_CSUM        = (1 << 4)
} RdmadevSendFlags;

typedef struct RdmadevSendWr {
    uint64_t wr_id;
    RdmadevWrOpcode opcode;
    uint32_t send_flags; /* RdmadevSendFlags */
    union {
        uint32_t imm_data; /* big endian */
        uint32_t invalidate_rkey;
    } ex;
    union {
        struct {
            uint64_t remote_addr;
            uint32_t rkey;
        } rdma;
        struct {
            uint64_t remote_addr;
            uint64_t compare_add;
            uint64_t swap;
            uint32_t rkey;
        } atomic;
        struct {
            uint32_t remote_qpn;
            uint32_t remote_qkey;
            uint32_t ah_handle;
        } ud;
        struct {
            uint32_t rkey;
            uint32_t access;
            uint32_t length;
            uint32_t page_shift;
            uint64_t iova;
            uint32_t sg_num;
            struct iovec *sg;
        } fast_reg;
    } wr;

    uint32_t num_sge;
    RdmadevSge sge[];
} RdmadevSendWr;

static inline uint32_t rdmadev_send_wr_size(uint32_t max_send_sge)
{
    return sizeof(RdmadevSendWr) + sizeof(RdmadevSge) * max_send_sge;
}

typedef enum RdmadevWcStatus {
    RDMADEV_WC_SUCCESS,
    RDMADEV_WC_LOC_LEN_ERR,
    RDMADEV_WC_LOC_QP_OP_ERR,
    RDMADEV_WC_LOC_EEC_OP_ERR,
    RDMADEV_WC_LOC_PROT_ERR,
    RDMADEV_WC_WR_FLUSH_ERR,
    RDMADEV_WC_MW_BIND_ERR,
    RDMADEV_WC_BAD_RESP_ERR,
    RDMADEV_WC_LOC_ACCESS_ERR,
    RDMADEV_WC_REM_INV_REQ_ERR,
    RDMADEV_WC_REM_ACCESS_ERR,
    RDMADEV_WC_REM_OP_ERR,
    RDMADEV_WC_RETRY_EXC_ERR,
    RDMADEV_WC_RNR_RETRY_EXC_ERR,
    RDMADEV_WC_LOC_RDD_VIOL_ERR,
    RDMADEV_WC_REM_INV_RD_REQ_ERR,
    RDMADEV_WC_REM_ABORT_ERR,
    RDMADEV_WC_INV_EECN_ERR,
    RDMADEV_WC_INV_EEC_STATE_ERR,
    RDMADEV_WC_FATAL_ERR,
    RDMADEV_WC_RESP_TIMEOUT_ERR,
    RDMADEV_WC_GENERAL_ERR,

    RDMADEV_WC_STATUS_MAX
} RdmadevWcStatus;

typedef enum RdmadevWcOpcode {
    RDMADEV_WC_SEND,
    RDMADEV_WC_RDMA_WRITE,
    RDMADEV_WC_RDMA_READ,
    RDMADEV_WC_COMP_SWAP,
    RDMADEV_WC_FETCH_ADD,
    RDMADEV_WC_BIND_MW,
    RDMADEV_WC_LOCAL_INV,
    RDMADEV_WC_LSO,
    RDMADEV_WC_ATOMIC_WRITE,
    RDMADEV_WC_REG_MR,
    RDMADEV_WC_MASKED_COMP_SWAP,
    RDMADEV_WC_MASKED_FETCH_ADD,
    RDMADEV_WC_FLUSH,
    RDMADEV_WC_RECV,
    RDMADEV_WC_RECV_RDMA_WITH_IMM,

    RDMADEV_WC_OPCODE_MAX
} RdmadevWcOpcode;

static inline const char *rdmadev_wc_opcode(RdmadevWcOpcode opcode)
{
    static const char *wc_opcode[] = {
        "SEND",
        "RDMA-WRITE",
        "RDMA-READ",
        "COMP-SWAP",
        "FETCH-ADD",
        "BIND-MW",
        "LOCAL-INV",
        "LSO",
        "ATOMIC-WRITE",
        "REG-MR",
        "MASKED-COMP-SWAP",
        "MASKED-FETCH-ADD",
        "FLUSH",
        "RECV",
        "RECV-RDMA-WITH-IMM" };

    assert(opcode < RDMADEV_WC_OPCODE_MAX);
    return wc_opcode[opcode];
}

typedef enum RdmadevWcFlags {
    RDMADEV_WC_GRH                   = (1 << 0),
    RDMADEV_WC_WITH_IMM              = (1 << 1),
    RDMADEV_WC_WITH_INVALIDATE       = (1 << 2),
    RDMADEV_WC_IP_CSUM_OK            = (1 << 3),
    RDMADEV_WC_WITH_SMAC             = (1 << 4),
    RDMADEV_WC_WITH_VLAN             = (1 << 5),
    RDMADEV_WC_WITH_NETWORK_HDR_TYPE = (1 << 6),
} RdmadevWcFlags;

typedef enum RdmadevNetworkType {
    RDMADEV_NETWORK_IB,
    RDMADEV_NETWORK_ROCE_V1,
    RDMADEV_NETWORK_IPV4,
    RDMADEV_NETWORK_IPV6
} RdmadevNetworkType;

typedef struct RdmadevWc {
    uint64_t wr_id;
    uint32_t qp_handle;
    uint32_t remote_qp_handle;
    uint32_t byte_len;
    uint32_t wc_flags; /* RdmadevWcFlags */
    union {
        uint32_t imm_data; /* big endian */
        uint32_t invalidate_rkey;
    } ex;
    RdmadevWcOpcode opcode;
    RdmadevWcStatus status;
    uint16_t pkey_index;
    uint16_t slid;
    uint8_t sl;
    uint8_t dlid_path_bits;
    RdmadevNetworkType network_hdr_type;

    void *wr;
} RdmadevWc;

#endif
