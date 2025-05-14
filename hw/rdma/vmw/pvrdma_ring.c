/*
 * QEMU VMW PVRDMA - Device rings
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

#include "qemu/atomic.h"
#include "hw/pci/pci.h"

#include "pvrdma.h"

int pvrdma_ring_init(PvrdmaRing *ring,
                                const char *name, PCIDevice *pdev,
				uint32_t max_elems,
				uint32_t elem_sz,
                                dma_addr_t dir_addr, uint32_t num_pages, uint32_t skip_pages)
{
    pvrdma_ring_state *ring_state;
    uint64_t *dir, *tbl;
    uint32_t elems;
    uint32_t elem_page = 1 + skip_pages; /* skip page[0] for ring_state */
    int ret = 0;

    /* page[0] for ring state(pvrdma_ring), at least 1 page for ring space */
    if (num_pages < 2) {
        pvrdma_error_report("Ring %s pages at least 2", name);
        return -EINVAL;
    }

    if (num_pages > PVRDMA_DMA_PAGES) {
        pvrdma_error_report("Ring %s maximum pages on a single directory must not exceed %d\n", name,
                          PVRDMA_DMA_PAGES);
        return -EINVAL;
    }

    /* XXX max_elems = pow2floor(max_elems); this is needed in theory.
     * however the dev-cq/async ring is wrong linux kernel driver */
    elems = (num_pages - elem_page) * qemu_target_page_size() / elem_sz;
    if (max_elems > elems) {
        pvrdma_error_report("Ring %s requires %d elements, exceeds %d\n", name,
                          max_elems, elems);
        return -EINVAL;
    }

    dir = pvrdma_pci_dma_map_page(pdev, dir_addr);
    if (!dir) {
        pvrdma_error_report("Failed to map to page directory (ring %s)", name);
        ret = -ENOMEM;
        goto out;
    }

    /* We support only one page table for a ring */
    tbl = pvrdma_pci_dma_map_page(pdev, dir[0]);
    if (!tbl) {
        pvrdma_error_report("Ring %s failed to map to page table", name);
        ret = -ENOMEM;
        goto out_free_dir;
    }

    ring_state = pvrdma_pci_dma_map_page(pdev, tbl[0]);
    if (!ring_state) {
        pvrdma_error_report("Ring %s failed to map to ring state", name);
        ret = -ENOMEM;
        goto out_free_tbl;
    }

    ring->pages = pvrdma_pci_map_pages(pdev, (dma_addr_t *)&tbl[elem_page], num_pages - elem_page);
    if (!ring->pages) {
        goto out_free_ring_state;
    }

    strncpy(ring->name, name, sizeof(ring->name) - 1);
    ring->dev = pdev;
    ring->elem_sz = elem_sz;
    ring->max_elems = max_elems;
    ring->npages = num_pages - 1 - skip_pages;
    ring->ring_state = ring_state;
    goto out_free_tbl;

out_free_ring_state:
    pvrdma_pci_dma_unmap_page(pdev, ring_state);

out_free_tbl:
    pvrdma_pci_dma_unmap_page(pdev, tbl);

out_free_dir:
    pvrdma_pci_dma_unmap_page(pdev, dir);

out:
    return ret;
}

void pvrdma_ring_free(PvrdmaRing *ring)
{
    if (!ring) {
        return;
    }

    if (ring->ring_state) {
        pvrdma_pci_dma_unmap_page(ring->dev, ring->ring_state);
    }

    if (!ring->pages) {
        return;
    }

    while (ring->npages--) {
        pvrdma_pci_dma_unmap_page(ring->dev, ring->pages[ring->npages]);
    }

    g_free(ring->pages);
    ring->pages = NULL;
}

void *pvrdma_ring_cons_next(PvrdmaRing *ring, struct pvrdma_ring *r, uint32_t *idx)
{
    const uint32_t tail = qatomic_read(&r->prod_tail);
    const uint32_t head = qatomic_read(&r->cons_head);
    uint32_t page_size = qemu_target_page_size();
    unsigned int offset;

    if (tail & ~((ring->max_elems << 1) - 1) ||
        head & ~((ring->max_elems << 1) - 1) ||
        tail == head) {
        return NULL;
    }

    *idx = head & (ring->max_elems - 1);
    offset = *idx * ring->elem_sz;
    return ring->pages[offset / page_size] + (offset % page_size);
}

void pvrdma_ring_cons_inc(PvrdmaRing *ring, struct pvrdma_ring *r)
{
    uint32_t idx = qatomic_read(&r->cons_head);

    idx = (idx + 1) & ((ring->max_elems << 1) - 1);
    qatomic_set(&r->cons_head, idx);
}

void *pvrdma_ring_prod_next(PvrdmaRing *ring, struct pvrdma_ring *r)
{
    const uint32_t tail = qatomic_read(&r->prod_tail);
    const uint32_t head = qatomic_read(&r->cons_head);
    uint32_t page_size = qemu_target_page_size();
    unsigned int idx, offset;

    if (tail & ~((ring->max_elems << 1) - 1) ||
        head & ~((ring->max_elems << 1) - 1) ||
        tail == (head ^ ring->max_elems)) {
        pvrdma_error_report("%s RX is full for next elem write", ring->name);
        return NULL;
    }

    idx = tail & (ring->max_elems - 1);
    offset = idx * ring->elem_sz;
    return ring->pages[offset / page_size] + (offset % page_size);
}

void pvrdma_ring_prod_inc(PvrdmaRing *ring, struct pvrdma_ring *r)
{
    uint32_t idx = qatomic_read(&r->prod_tail);

    idx = (idx + 1) & ((ring->max_elems << 1) - 1);
    qatomic_set(&r->prod_tail, idx);
}
