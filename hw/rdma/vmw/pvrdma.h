/*
 * QEMU VMW PVRDMA
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

#ifndef PVRDMA_PVRDMA_H
#define PVRDMA_PVRDMA_H

#include "exec/target_page.h"
#include "hw/net/vmxnet3_defs.h"
#include "hw/pci/pci_device.h"
#include "qemu/error-report.h"
#include "rdma/rdma.h"
#include "pvrdma_dev_api.h"
#include "vmw_pvrdma-abi.h"

#define pvrdma_error_report(fmt, ...) \
    error_report("%s: " fmt, "pvrdma", ## __VA_ARGS__)
#define pvrdma_warn_report(fmt, ...) \
    warn_report("%s: " fmt, "pvrdma", ## __VA_ARGS__)
#define pvrdma_info_report(fmt, ...) \
    info_report("%s: " fmt, "pvrdma", ## __VA_ARGS__)

/* pvrdma_ring.c */
/*
 * pvrdma_ring/pvrdma_ring_state
 * see linux/drivers/infiniband/hw/vmw_pvrdma/pvrdma_ring.h
 * once the two structures get exported from ABI files, include ABI file instead
 */
typedef struct pvrdma_ring {
    uint32_t prod_tail; /* producer tail */
    uint32_t cons_head; /* consumer head */
} pvrdma_ring;

typedef struct pvrdma_ring_state {
        struct pvrdma_ring tx;  /* Tx ring. */
        struct pvrdma_ring rx;  /* Rx ring. */
} pvrdma_ring_state;

#define PVRDMA_RING_NAME_SIZE 32
typedef struct PvrdmaRing {
    char name[PVRDMA_RING_NAME_SIZE];
    PCIDevice *dev;
    uint32_t elem_sz;
    uint32_t max_elems;
    uint32_t npages;
    pvrdma_ring_state *ring_state;
    void **pages;
} PvrdmaRing;


int pvrdma_ring_init(PvrdmaRing *ring,
                                const char *name, PCIDevice *pdev,
                                uint32_t max_elems,
                                uint32_t elem_sz,
                                dma_addr_t dir_addr, uint32_t num_pages, uint32_t skip_pages);
void pvrdma_ring_free(PvrdmaRing *ring);
void *pvrdma_ring_cons_next(PvrdmaRing *ring, struct pvrdma_ring *r, uint32_t *idx);
void pvrdma_ring_cons_inc(PvrdmaRing *ring, struct pvrdma_ring *r);
void *pvrdma_ring_prod_next(PvrdmaRing *ring, struct pvrdma_ring *r);
void pvrdma_ring_prod_inc(PvrdmaRing *ring, struct pvrdma_ring *r);

static inline void *pvrdma_ring_tx_next(PvrdmaRing *ring, uint32_t *idx)
{
    return pvrdma_ring_cons_next(ring, &ring->ring_state->tx, idx);
}

static inline void pvrdma_ring_tx_inc(PvrdmaRing *ring)
{
    return pvrdma_ring_cons_inc(ring, &ring->ring_state->tx);
}

static inline void *pvrdma_ring_rx_next(PvrdmaRing *ring)
{
    return pvrdma_ring_prod_next(ring, &ring->ring_state->rx);
}

static inline void pvrdma_ring_rx_inc(PvrdmaRing *ring)
{
    return pvrdma_ring_prod_inc(ring, &ring->ring_state->rx);
}


/* pvrdma.c */
typedef struct PVRDMADev {
    PCIDevice parent_obj;

    MemoryRegion msix;

    uint32_t regs_data[16];
    MemoryRegion regs;

    uint32_t max_uar;
    uint32_t *uar_data;
    MemoryRegion uar;

    dma_addr_t dsr_dma;
    struct pvrdma_device_shared_region *dsr;

    union pvrdma_cmd_req *cmd_slot;
    union pvrdma_cmd_resp *resp_slot;

    /* async event ring */
    PvrdmaRing async_ring;

    /* devcie CQ ring */
    PvrdmaRing cq_ring;

    uint32_t interrupt_mask;
    VMXNET3State *func0;

    /* backend rdmadev */
    Rdmadev *rdev;
} PVRDMADev;

#define PVRDMA_NAME "pvrdma"
DECLARE_INSTANCE_CHECKER(PVRDMADev, PVRDMA_DEV, PVRDMA_NAME)

void *pvrdma_pci_dma_map(PCIDevice *pdev, dma_addr_t addr, dma_addr_t len);

static inline void *pvrdma_pci_dma_map_page(PCIDevice *pdev, dma_addr_t addr)
{
    return pvrdma_pci_dma_map(pdev, addr, qemu_target_page_size());
}

void pvrdma_pci_dma_unmap(PCIDevice *pdev, void *buffer, dma_addr_t len);

static inline void pvrdma_pci_dma_unmap_page(PCIDevice *pdev, void *buffer)
{
    pvrdma_pci_dma_unmap(pdev, buffer, qemu_target_page_size());
}

void **pvrdma_pci_map_pages(PCIDevice *dev, dma_addr_t *tbl, uint32_t npages);

void pvrdma_post_interrupt(PVRDMADev *dev, uint32_t vector);

/* Default features/limitations */
#define PVRDMA_PKEY          0xFFFF
#define PVRDMA_PKEYS         1

/* XXX support 1 dir only */
#define PVRDMA_DMA_PAGES ((1 << PVRDMA_PTABLE_SHIFT))

static inline uint32_t pvrdma_max_cqe(PVRDMADev *dev)
{
    uint32_t max_pages = PVRDMA_DMA_PAGES - 1; /* page[0] for ring state */
    uint32_t max_cqe = max_pages * qemu_target_page_size() / sizeof(struct pvrdma_cqe);

    max_cqe = MIN(max_cqe, dev->rdev->dev_attr.max_cqe);
    return pow2floor(max_cqe);
}

static inline uint32_t pvrdma_gid_tbl_len(PVRDMADev *dev)
{
    RdmaPortAttr port_attr;

    rdmadev_query_port(dev->rdev, 1, &port_attr);

    return MIN(4, port_attr.gid_tbl_len);
}


/* pvrdma_qp.c */
void pvrdma_post_send(PVRDMADev *dev, uint32_t qp_handle);
void pvrdma_post_recv(PVRDMADev *dev, uint32_t qp_handle);
void pvrdma_post_srq_recv(PVRDMADev *dev, uint32_t srq_handle);
void pvrdma_cq_complete(void *hwdev, RdmadevWc *wc, int cq, void *cq_ctx);


/* pvrdma_cmd.c */
int pvrdma_exec_cmd(PVRDMADev *dev);

#endif
