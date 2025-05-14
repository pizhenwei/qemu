/*
 * QEMU RDMA Device Emulation Support
 *
 * Copyright (c) 2023 Bytedance
 *
 * Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"

#if 0
static void rdma_device_init(Object *obj)
{
    RdmaDevice *rdev = RDMA_DEVICE(obj);

    printf("always: %s, %d, rdev %p\n", __func__, __LINE__, rdev);
}

static void rdma_device_finalize(Object *obj)
{
    RdmaDevice *rdev = RDMA_DEVICE(obj);

    printf("always: %s, %d, rdev %p\n", __func__, __LINE__, rdev);
}

static Property rdma_device_properties[] = {
    DEFINE_PROP_LINK("rdmadev", RdmaDevice, dev, TYPE_RDMADEV, Rdmadev *),
    DEFINE_PROP_END_OF_LIST(),
};

static void rdma_device_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    RdmaDeviceClass *rdc = RDMA_DEVICE_CLASS(oc);

    device_class_set_props(dc, rdma_device_properties);
    printf("always: %s, %d, rdc %p\n", __func__, __LINE__, rdc);
}

static const TypeInfo rdma_device_info = {
    .name = TYPE_RDMA_DEVICE,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(RdmaDevice),
    .instance_init = rdma_device_init,
    .instance_finalize = rdma_device_finalize,
    .abstract = true,
    .class_init = rdma_device_class_init,
    .class_size = sizeof(RdmaDeviceClass),
};

static void rdma_device_register_types(void)
{
    printf("always: %s, %d\n", __func__, __LINE__);
    type_register_static(&rdma_device_info);
}

type_init(rdma_device_register_types)
#endif
