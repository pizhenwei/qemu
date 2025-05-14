/*
 * QEMU VMW PVRDMA - Device implementation
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

#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "pvrdma_dev_api.h"
#include "vmw_pvrdma-abi.h"

#include "hw/pci/pci.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/qdev-properties.h"
#include "rdma/rdma.h"
#include "rdma/rdma-utils.h"
#include "qom/object_interfaces.h"

#include "trace.h"
#include "pvrdma.h"
#include "pvrdma-types.h"

/* MSIX */
#define PVRDMA_MSIX_SIZE  (16 * KiB)
#define PVRDMA_MSIX_TABLE 0x0000
#define PVRDMA_MSIX_PBA   0x2000

/* HW attributes */
#define PVRDMA_FW_VERSION    14

void *pvrdma_pci_dma_map(PCIDevice *pdev, dma_addr_t addr, dma_addr_t len)
{
    void *p;
    dma_addr_t plen = len;

    if (!addr || !len) {
        pvrdma_error_report("Invalid DMA map request");
        return NULL;
    }

    p = pci_dma_map(pdev, addr, &plen, DMA_DIRECTION_TO_DEVICE);
    if (!p) {
        pvrdma_error_report("pci_dma_map fail, addr=0x%"PRIx64", len=%"PRId64,
                            addr, plen);
        return NULL;
    }

    if (plen != len) {
        pvrdma_error_report("pci_dma_map unexpected length %"PRId64" against %"PRId64" at addr 0x%"PRIx64, plen, len, addr);
        pvrdma_pci_dma_unmap(pdev, p, plen);
        return NULL;
    }

    trace_pvrdma_pci_dma_map((uint64_t)p, (uint32_t)len, addr);
    return p;
}

void pvrdma_pci_dma_unmap(PCIDevice *pdev, void *buffer, dma_addr_t len)
{
    trace_pvrdma_pci_dma_unmap((uint64_t)buffer, (uint32_t)len);

    if (buffer) {
        pci_dma_unmap(pdev, buffer, len, DMA_DIRECTION_TO_DEVICE, 0);
    }
}

void **pvrdma_pci_map_pages(PCIDevice *dev, dma_addr_t *tbl, uint32_t npages)
{
    void **pages;
    int i;

    pages = g_new0(void *, npages);

    for (i = 0; i < npages; i++) {
        if (!tbl[i]) {
            goto error;
        }

        pages[i] = pvrdma_pci_dma_map_page(dev, tbl[i]);
        if (!pages[i]) {
            goto error;
        }
        /* XXX memset(pages[i], 0, qemu_target_page_size()) is required? */
    }

    return pages;

error:
    while (i--) {
        pvrdma_pci_dma_unmap_page(dev, pages[i]);
    }
    g_free(pages);

    return NULL;
}

static void *__pvrdma_pci_dma_map(void *dev, dma_addr_t addr, dma_addr_t len)
{
    PCIDevice *pdev = PCI_DEVICE(dev);

    return pvrdma_pci_dma_map(pdev, addr, len);
}

static void __pvrdma_pci_dma_unmap(void *dev, void *buffer, dma_addr_t len)
{
    PCIDevice *pdev = PCI_DEVICE(dev);

    pvrdma_pci_dma_unmap(pdev, buffer, len);
}

void pvrdma_post_interrupt(PVRDMADev *dev, uint32_t vector)
{
    PCIDevice *pdev = PCI_DEVICE(dev);

    trace_pvrdma_post_interrupt(vector);
    if (likely(!(dev->interrupt_mask & (1 << vector)))) {
        msix_notify(pdev, vector);
    }
}

static int pvrdma_get_reg_val(PVRDMADev *dev, uint32_t off, uint32_t *val)
{
    if (off >= sizeof(dev->regs_data)) {
        pvrdma_error_report("Failed to read REG value");
        return -EINVAL;
    }

    *val = dev->regs_data[off >> 2];
    trace_pvrdma_get_reg_val(off, *val);
    return 0;
}

static int pvrdma_set_reg_val(PVRDMADev *dev, uint32_t off, uint32_t val)
{
    if (off >= sizeof(dev->regs_data)) {
        return -EINVAL;
    }

    dev->regs_data[off >> 2] = val;
    trace_pvrdma_set_reg_val(off, val);
    return 0;
}

static void pvrdma_free_dsr(PVRDMADev *dev)
{
    PCIDevice *pdev = PCI_DEVICE(dev);

    if (!dev->dsr) {
        return;
    }

    pvrdma_pci_dma_unmap(pdev, dev->dsr, sizeof(*dev->dsr));
    dev->dsr = NULL;

    pvrdma_pci_dma_unmap_page(pdev, dev->cmd_slot);
    pvrdma_pci_dma_unmap_page(pdev, dev->resp_slot);

    pvrdma_ring_free(&dev->async_ring);
    pvrdma_ring_free(&dev->cq_ring);
}

static int pvrdma_find_vmxnet3(PVRDMADev *dev)
{
    PCIDevice *pdev = PCI_DEVICE(dev);
    PCIDevice *func0;
    Rdmadev *rdev = dev->rdev;
    RdmaPortAttr attr;

    func0 = pci_get_function_0(pdev);
    if (!func0) {
        pvrdma_error_report("Failed to find PCI func0 for net device");
        return -ENOMEM;
    }

    if (strcmp(object_get_typename(OBJECT(func0)), TYPE_VMXNET3)) {
        pvrdma_error_report("Device on %x.0 must be %s", PCI_SLOT(pdev->devfn),
                   TYPE_VMXNET3);
        return -ENODEV;
    }

    dev->func0 = VMXNET3(func0);
    rdmadev_init_port(dev->rdev, 1, dev->func0->nic);

    if (rdmadev_query_port(rdev, 1, &attr)) {
        pvrdma_error_report("Invalid port");
        return -EIO;
    }

    if (attr.link_layer != RDMADEV_LINK_LAYER_ETHERNET) {
        pvrdma_error_report("RoCE is required");
        return -EIO;
    }

    return 0;
}

static void pvrdma_dsr_caps(PVRDMADev *dev)
{
    struct pvrdma_device_caps *caps = &dev->dsr->caps;
    RdmaDevAttr *dev_attr = &dev->rdev->dev_attr;

    caps->fw_ver = PVRDMA_FW_VERSION;
    rdmadev_addrconf_eui48((unsigned char *)&caps->node_guid,
                    (const char *)&dev->func0->conf.macaddr.a);
    caps->sys_image_guid = 0;
    caps->max_mr_size = dev_attr->max_mr_size;
    caps->page_size_cap =  qemu_target_page_mask();
    caps->atomic_arg_sizes = 0;
    caps->ex_comp_mask = 0;
    caps->device_cap_flags2 = 0;
    caps->max_fa_bit_boundary = 0;
    caps->log_max_atomic_inline_arg = 0;
    caps->vendor_id = PCI_VENDOR_ID_VMWARE;
    caps->vendor_part_id = PCI_DEVICE_ID_VMWARE_PVRDMA;
    caps->hw_ver = PVRDMA_PPN64_VERSION;
    caps->max_qp = dev_attr->max_qp;
    caps->max_qp_wr = dev_attr->max_qp_wr;
    caps->device_cap_flags = pvrdma_device_cap_flags(dev_attr->device_cap_flags);
    caps->device_cap_flags |= (1 << 21); /* MEM_MGT_EXTENSIONS */
    caps->max_sge = dev_attr->max_sge;
    caps->max_sge_rd = dev_attr->max_sge_rd;
    caps->max_cq = dev_attr->max_cq;
    caps->max_cqe = pvrdma_max_cqe(dev);
    caps->max_mr = dev_attr->max_mr;
    caps->max_pd = dev_attr->max_pd;
    caps->max_qp_rd_atom = dev_attr->max_qp_rd_atom;
    caps->max_ee_rd_atom = dev_attr->max_ee_rd_atom;
    caps->max_res_rd_atom = dev_attr->max_res_rd_atom;
    caps->max_qp_init_rd_atom = dev_attr->max_qp_init_rd_atom;
    caps->max_ee_init_rd_atom = dev_attr->max_ee_init_rd_atom;
    caps->max_ee = 0;
    caps->max_rdd = 0;
    caps->max_mw = 0; /* MW is not supported by PVRDMA */
    caps->max_raw_ipv6_qp = 0;
    caps->max_raw_ethy_qp = 0;
    caps->max_mcast_grp = 0;
    caps->max_mcast_qp_attach = 0;
    caps->max_total_mcast_qp_attach = 0;
    caps->max_ah = dev_attr->max_ah;
    caps->max_fmr = 0;
    caps->max_map_per_fmr = 0;
    caps->max_srq = dev_attr->max_srq;
    caps->max_srq_wr = dev_attr->max_srq_wr;
    caps->max_srq_sge = dev_attr->max_srq_sge;
    caps->max_uar = dev->max_uar;
    caps->gid_tbl_len = pvrdma_gid_tbl_len(dev);
    caps->max_pkeys = MIN(PVRDMA_PKEYS, dev_attr->max_pkeys);
    caps->local_ca_ack_delay = dev_attr->local_ca_ack_delay;
    caps->phys_port_cnt = dev_attr->phys_port_cnt;
    caps->mode = PVRDMA_DEVICE_MODE_ROCE;
    if ((dev_attr->atomic_cap == RDMADEV_ATOMIC_CAP_HCA) ||
        (dev_attr->atomic_cap == RDMADEV_ATOMIC_CAP_GLOB)) {
        caps->atomic_ops = PVRDMA_ATOMIC_OP_COMP_SWAP;
        caps->atomic_ops |= PVRDMA_ATOMIC_OP_FETCH_ADD;
    }
    caps->bmme_flags = PVRDMA_BMME_FLAG_LOCAL_INV | PVRDMA_BMME_FLAG_REMOTE_INV;
    caps->bmme_flags |= PVRDMA_BMME_FLAG_FAST_REG_WR;
    caps->max_fast_reg_page_list_len = PVRDMA_DMA_PAGES - 1;
    caps->gid_types = PVRDMA_GID_TYPE_FLAG_ROCE_V2;
}

static int pvrdma_new_dsr(PVRDMADev *dev)
{
    PCIDevice *pdev = PCI_DEVICE(dev);
    struct pvrdma_device_shared_region *dsr;
    int ret = -ENOMEM;
    uint32_t max_elems;

    pvrdma_free_dsr(dev);

    /* Map to DSR */
    dsr = dev->dsr = pvrdma_pci_dma_map(pdev, dev->dsr_dma, sizeof(*dev->dsr));
    if (!dev->dsr) {
        pvrdma_error_report("Failed to map to DSR");
        return -ENOMEM;
    }

    ret = pvrdma_find_vmxnet3(dev);
    if (ret) {
        dsr->caps.mode = 0xff; /* invalid mode, guest should give up */
        pvrdma_set_reg_val(dev, PVRDMA_REG_ERR, 0xFFFF);
        return ret;
    }

    /* Map to command slot */
    dev->cmd_slot = pvrdma_pci_dma_map_page(pdev, dsr->cmd_slot_dma);
    if (!dev->cmd_slot) {
        pvrdma_error_report("Failed to map to command slot address");
        goto error;
    }

    /* Map to response slot */
    dev->resp_slot = pvrdma_pci_dma_map_page(pdev, dsr->resp_slot_dma);
    if (!dev->resp_slot) {
        pvrdma_error_report("Failed to map to response slot address");
        goto error;
    }

    /* Map to CQ notification ring */
    max_elems = (dsr->cq_ring_pages.num_pages - 1) * qemu_target_page_size() / sizeof(struct pvrdma_cqne);
    ret = pvrdma_ring_init(&dev->cq_ring, "dev-cq", pdev, max_elems,
                           sizeof(struct pvrdma_cqne),
                           dsr->cq_ring_pages.pdir_dma,
                           dsr->cq_ring_pages.num_pages, 0);
    if (ret) {
        goto error;
    }

    /* Map to event notification ring */
    max_elems = (dsr->async_ring_pages.num_pages - 1) * qemu_target_page_size() / sizeof(struct pvrdma_eqe);
    ret = pvrdma_ring_init(&dev->async_ring, "dev-async", pdev, max_elems,
                           sizeof(struct pvrdma_eqe),
                           dsr->async_ring_pages.pdir_dma,
                           dsr->async_ring_pages.num_pages, 0);
    if (ret) {
        goto error;
    }

    /* set device caps into DSR */
    pvrdma_dsr_caps(dev);

    return 0;

error:
    pvrdma_free_dsr(dev);
    return ret;
}

static void pvrdma_activate_device(PVRDMADev *dev)
{
    trace_pvrdma_activate_device();
    pvrdma_set_reg_val(dev, PVRDMA_REG_ERR, 0);
}

static int pvrdma_unquiesce_device(PVRDMADev *dev)
{
    trace_pvrdma_unquiesce_device();
    return 0;
}

static void pvrdma_reset_device(PVRDMADev *dev)
{
    trace_pvrdma_reset_device();
}

static uint64_t pvrdma_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    PVRDMADev *dev = opaque;
    uint32_t val = 0;

    switch (addr) {
    case PVRDMA_REG_VERSION:
    case PVRDMA_REG_ERR:
        pvrdma_get_reg_val(dev, addr, &val);
        break;
    case PVRDMA_REG_ICR:
        pvrdma_warn_report("MSI-X in use, ICR should not access");
        break;
    default:
        pvrdma_warn_report("Unsupported REG reading");
    }

    return val;
}

static void pvrdma_regs_write(void *opaque, hwaddr addr, uint64_t val,
                              unsigned size)
{
    PVRDMADev *dev = opaque;
    int ret;

    if (pvrdma_set_reg_val(dev, addr, val)) {
        error_report("pvrdma: Failed to set REG value, addr=0x%"PRIx64 ", val=0x%"PRIx64,
                          addr, val);
        return;
    }

    switch (addr) {
    case PVRDMA_REG_DSRLOW:
        dev->dsr_dma = val;
        break;
    case PVRDMA_REG_DSRHIGH:
        dev->dsr_dma |= val << 32;
        pvrdma_new_dsr(dev);
        break;
    case PVRDMA_REG_CTL:
        switch (val) {
        case PVRDMA_DEVICE_CTL_ACTIVATE:
            pvrdma_activate_device(dev);
            break;
        case PVRDMA_DEVICE_CTL_UNQUIESCE:
            pvrdma_unquiesce_device(dev);
            break;
        case PVRDMA_DEVICE_CTL_RESET:
            pvrdma_reset_device(dev);
            break;
        }
        break;
    case PVRDMA_REG_REQUEST:
        ret = pvrdma_exec_cmd(dev);
        pvrdma_set_reg_val(dev, PVRDMA_REG_ERR, ret);
        pvrdma_post_interrupt(dev, 0); /* intr0 for CMD execution */
        break;
    case PVRDMA_REG_IMR:
        dev->interrupt_mask = val;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps pvrdma_regs_ops = {
    .read = pvrdma_regs_read,
    .write = pvrdma_regs_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = sizeof(uint32_t),
        .max_access_size = sizeof(uint32_t),
    },
};

static uint64_t pvrdma_uar_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0xffffffff;
}

static void pvrdma_uar_write(void *opaque, hwaddr addr, uint64_t val,
                             unsigned size)
{
    PVRDMADev *dev = opaque;
    uint32_t qp_handle;

    switch (addr & 0xFFF) { /* Mask with 0xFFF as each UC gets page */
    case PVRDMA_UAR_QP_OFFSET:
        qp_handle = val & PVRDMA_UAR_HANDLE_MASK;
        if (val & PVRDMA_UAR_QP_SEND) {
            pvrdma_post_send(dev, qp_handle);
        }
        if (val & PVRDMA_UAR_QP_RECV) {
            pvrdma_post_recv(dev, qp_handle);
        }
        break;
    case PVRDMA_UAR_CQ_OFFSET:
        if (val & PVRDMA_UAR_CQ_ARM) {
            rdmadev_req_notify_cq(dev->rdev, val & PVRDMA_UAR_HANDLE_MASK, 0);
        }
        if (val & PVRDMA_UAR_CQ_ARM_SOL) {
            rdmadev_req_notify_cq(dev->rdev, val & PVRDMA_UAR_HANDLE_MASK, 0);
        }
        if (val & PVRDMA_UAR_CQ_POLL) {
            rdmadev_poll_cq(dev->rdev, val & PVRDMA_UAR_HANDLE_MASK);
        }
        break;
    case PVRDMA_UAR_SRQ_OFFSET:
        if (val & PVRDMA_UAR_SRQ_RECV) {
            pvrdma_post_srq_recv(dev, val & PVRDMA_UAR_HANDLE_MASK);
        }
        break;
    default:
        pvrdma_error_report("Unsupported command, addr=0x%"PRIx64", val=0x%"PRIx64,
                          addr, val);
        break;
    }
}

static const MemoryRegionOps pvrdma_uar_ops = {
    .read = pvrdma_uar_read,
    .write = pvrdma_uar_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = sizeof(uint32_t),
        .max_access_size = sizeof(uint32_t),
    },
};

static int pvrdma_init_pci_res(PCIDevice *pdev, Error **errp)
{
    PVRDMADev *dev = PVRDMA_DEV(pdev);
    uint64_t uar_size;
    int ret;

    pdev->config[PCI_INTERRUPT_PIN] = 1;

    /* BAR 0 - MSI-X */
    memory_region_init(&dev->msix, OBJECT(dev), "pvrdma-msix",
                       PVRDMA_MSIX_SIZE);
    pci_register_bar(pdev, PVRDMA_PCI_RESOURCE_MSIX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &dev->msix);

    ret = msix_init(pdev, PVRDMA_MAX_INTERRUPTS, &dev->msix,
                    PVRDMA_PCI_RESOURCE_MSIX, PVRDMA_MSIX_TABLE, &dev->msix,
                    PVRDMA_PCI_RESOURCE_MSIX, PVRDMA_MSIX_PBA, 0, NULL);
    if (ret < 0) {
        error_setg(errp, "pvrdma: Failed to initialize MSI-X");
        return ret;
    }

    for (unsigned int i = 0; i < PVRDMA_MAX_INTERRUPTS; i++) {
        msix_vector_use(pdev, i);
    }

    /* BAR 1 - Registers */
    memory_region_init_io(&dev->regs, OBJECT(dev), &pvrdma_regs_ops, dev,
                          "pvrdma-regs", sizeof(dev->regs_data));
    pci_register_bar(pdev, PVRDMA_PCI_RESOURCE_REG,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &dev->regs);

    pvrdma_set_reg_val(dev, PVRDMA_REG_VERSION, PVRDMA_PPN64_VERSION);
    pvrdma_set_reg_val(dev, PVRDMA_REG_ERR, 0xFFFF);

    /* BAR 2 - UAR */
    uar_size = dev->max_uar * qemu_target_page_size();
    dev->uar_data = g_malloc0(uar_size);
    memory_region_init_io(&dev->uar, OBJECT(dev), &pvrdma_uar_ops, dev,
                          "pvrdma-uar", uar_size);
    pci_register_bar(pdev, PVRDMA_PCI_RESOURCE_UAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &dev->uar);

    return 0;
}

static void pvrdma_realize(PCIDevice *pdev, Error **errp)
{
    PVRDMADev *dev = PVRDMA_DEV(pdev);
    Rdmadev *rdev = dev->rdev;
    uint32_t uc_handle = 0;

    if (rdev->dev_attr.phys_port_cnt != 1) {
        error_setg(errp, "pvrdma: Support a single port");
        return;
    }

    rdev->hwdev = dev;
    rdev->cq_comp = pvrdma_cq_complete;
    rdev->dma_map = __pvrdma_pci_dma_map;
    rdev->dma_unmap = __pvrdma_pci_dma_unmap;
    if (rdmadev_init(rdev)) {
        error_setg(errp, "pvrdma: Failed to initialize backend rdmadev");
        return;
    }

    /* reserve uc handle 0 for pvrdma driver context */
    if (rdmadev_alloc_uc(rdev, uc_handle, NULL)) {
        error_setg(errp, "pvrdma: Failed to allocate uc handle 0");
        return;
    }

    if (pvrdma_init_pci_res(pdev, errp)) {
        return;
    }
}

static void pvrdma_device_finalize(Object *obj)
{
    //RdmaDevice *rdev = RDMA_DEVICE(obj);
}

static Property pvrdma_device_properties[] = {
    DEFINE_PROP_LINK("rdmadev", PVRDMADev, rdev, TYPE_RDMADEV, Rdmadev *),
    DEFINE_PROP_UINT32("max-uar", PVRDMADev, max_uar, 128),
    DEFINE_PROP_END_OF_LIST(),
};


static void pvrdma_device_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pcidc = PCI_DEVICE_CLASS(oc);

    device_class_set_props(dc, pvrdma_device_properties);
    dc->desc = "VMW PVRDMA Device";
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);

    pcidc->realize = pvrdma_realize;
    pcidc->vendor_id = PCI_VENDOR_ID_VMWARE;
    pcidc->device_id = PCI_DEVICE_ID_VMWARE_PVRDMA;
    pcidc->revision = 0x00;
    pcidc->class_id = PCI_CLASS_NETWORK_OTHER;
}

static const TypeInfo pvrdma_device_info = {
    .name = PVRDMA_NAME,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PVRDMADev),
    .instance_finalize = pvrdma_device_finalize,
    .class_init = pvrdma_device_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    }
};

static void pvrdma_device_register_types(void)
{
    type_register_static(&pvrdma_device_info);
}

type_init(pvrdma_device_register_types)
