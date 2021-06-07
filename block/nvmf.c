/*
 * NVMe over fabric block driver based on libnvmf
 *
 * Copyright 2020-2021 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include <poll.h>
#include "qemu/error-report.h"
#include "block/block_int.h"
#include "block/nvme.h"
#include "qemu/iov.h"
#include "qemu/option.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"

#include "nvmf/nvmf.h"

#define DEF_IO_QUEUES        4          /* default IO queues 4 by RR policy */
#define NVMF_KATO            30000      /* default keepalive time 30s */
#define NVMF_URI             "uri"
#define PROTOCOL_TCP_PREF    "nvmf-tcp://"
#define PROTOCOL_RDMA_PREF   "nvmf-rdma://"

typedef struct NvmfQueue {
    int qid;
    CoQueue wait_queue;
    CoMutex wait_lock;
} NvmfQueue;

typedef struct NvmfHost {
    nvmf_options_t opts;
    nvmf_ctrl_t ctrl;
    AioContext *aio_context;
    QemuSpin lock;

    unsigned long requests;
    int nr_ioqueues;
    NvmfQueue *ioqueues;
} NvmfHost;

typedef struct NvmfReq {
    NvmfHost *host;
    nvmf_req_t req;
    Coroutine *co;
    int qid;
    int retval;
    bool done;
} NvmfReq;

typedef enum NvmfOp {
    NvmfOpRead,
    NvmfOpWrite,
    NvmfOpDiscard,
    NvmfOpWritezeroes
} NvmfOp;

static void nvmf_process(void *opaque)
{
    NvmfHost *host = opaque;

    nvmf_ctrl_process(host->ctrl);
}

static void nvmf_attach_aio_context(BlockDriverState *bs,
                                    AioContext *new_context)
{
    NvmfHost *host = bs->opaque;

    host->aio_context = new_context;

    qemu_spin_lock(&host->lock);
    aio_set_fd_handler(new_context, nvmf_ctrl_fd(host->ctrl),
                       false, nvmf_process, NULL, NULL, host);
    qemu_spin_unlock(&host->lock);
}

static QemuOptsList runtime_opts = {
    .name = "nvmf",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = NVMF_URI,
            .type = QEMU_OPT_STRING,
            .help = "NVMe over fabric URI",
        },
        { /* end of list */ }
    },
};

static void nvmf_parse_filename(const char *filename, QDict *options,
                                Error **errp)
{
    const char *uri;
    int len;

    len = strlen(PROTOCOL_TCP_PREF);
    if (strlen(filename) > len && !strncmp(filename, PROTOCOL_TCP_PREF, len)) {
        uri = g_strdup(filename);
        qdict_put_str(options, NVMF_URI, uri);
        return;
    }

    len = strlen(PROTOCOL_RDMA_PREF);
    if (strlen(filename) > len && !strncmp(filename, PROTOCOL_RDMA_PREF, len)) {
        uri = g_strdup(filename);
        qdict_put_str(options, NVMF_URI, uri);
        return;
    }

    error_setg(errp, "nvmf: invalid filename. Ex, nvmf-tcp/nvmf-rdma");
}

static int nvmf_file_open(BlockDriverState *bs, QDict *options, int flags,
                          Error **errp)
{
    NvmfHost *host = bs->opaque;
    QemuOpts *qopts;
    nvmf_ctrl_t ctrl;
    nvmf_options_t opts;
    const char *uri;
    NvmfQueue *queue;
    unsigned int nsid;
    int i;

    qopts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(qopts, options, &error_abort);
    uri = qemu_opt_get(qopts, NVMF_URI);
    if (!uri) {
        error_setg(errp, "nvmf: missing URI");
        goto free_qopts;
    }

    host->nr_ioqueues = DEF_IO_QUEUES;
    opts = nvmf_default_options(uri, NULL);
    if (!opts) {
        error_setg(errp, "nvmf: parse uri failed");
        goto free_uri;
    }

    nvmf_options_set_io_queues(opts, host->nr_ioqueues);
    nvmf_options_set_kato(opts, NVMF_KATO);
    ctrl = nvmf_ctrl_create(opts);
    if (!ctrl) {
        error_setg(errp, "nvmf: create ctrl failed");
        goto free_nvmf_opts;
    }

    if (nvmf_ns_count(ctrl) < 1) {
        error_setg(errp, "nvmf: no available namespace");
        goto release_ctrl;
    }

    /* nsid should be specified by command line */
    nsid = nvmf_ns_id(ctrl);
    if (!nvmf_ns_lbads(ctrl, nsid)) {
        error_setg(errp, "nvmf: invalid LBADS");
        goto release_ctrl;
    }

    if (!nvmf_ns_nsze(ctrl, nsid)) {
        error_setg(errp, "nvmf: invalid size");
        goto release_ctrl;
    }

    host->ioqueues = g_new0(NvmfQueue, host->nr_ioqueues + 1);
    memset(host->ioqueues, 0x00, sizeof(NvmfQueue) * (host->nr_ioqueues + 1));
    for (i = 0; i < host->nr_ioqueues + 1; i++) {
        queue = host->ioqueues + i;
        queue->qid = i;
        qemu_co_mutex_init(&queue->wait_lock);
        qemu_co_queue_init(&queue->wait_queue);
    }

    host->ctrl = ctrl;
    host->opts = opts;
    qemu_spin_init(&host->lock);
    nvmf_attach_aio_context(bs, bdrv_get_aio_context(bs));
    g_free((void *)uri);

    return 0;

release_ctrl:
    nvmf_ctrl_release(ctrl);

free_nvmf_opts:
    nvmf_options_free(opts);

free_uri:
    g_free((void *)uri);

free_qopts:
    qemu_opts_del(qopts);

    return -EINVAL;
}

static void nvmf_close(BlockDriverState *bs)
{
    NvmfHost *host = bs->opaque;

    nvmf_ctrl_release(host->ctrl);
    nvmf_options_free(host->opts);
    g_free(host->ioqueues);
}

static inline bool nvmf_is_lba_aligned(nvmf_ctrl_t ctrl, size_t offset,
                                       size_t length)
{
    unsigned int nsid = nvmf_ns_id(ctrl);
    unsigned char lbads = nvmf_ns_lbads(ctrl, nsid);
    return !(offset & ((1 << lbads) - 1)) && !(length & ((1 << lbads) - 1));
}

static inline void nvmf_req_co_init(NvmfHost *host, NvmfReq *req)
{
    req->host = host;
    req->req = req;
    req->co = qemu_coroutine_self();
    req->done = false;
}

static void nvmf_req_cb(unsigned short status, void *opaque)
{
    NvmfReq *req = opaque;

    switch (status) {
    case NVME_SUCCESS:
        req->retval = 0;
        break;

    case NVME_INVALID_OPCODE:
        req->retval = -ENOSYS;
        break;

    case NVME_INVALID_FIELD:
        req->retval = -EINVAL;
        break;

    default:
        req->retval = -EIO;
        break;
    }

    req->done = true;
    aio_co_wake(req->co);
}

static coroutine_fn int nvmf_co_io(BlockDriverState *bs, uint64_t offset,
                                   uint64_t bytes, QEMUIOVector *qiov,
                                   int flags, NvmfOp op)
{
    NvmfHost *host = bs->opaque;
    NvmfQueue *queue;
    NvmfReq req;
    struct iovec iov = {.iov_base = NULL, .iov_len = bytes};
    int qid;

    if (!nvmf_is_lba_aligned(host->ctrl, offset, bytes)) {
        return -EINVAL;
    }
    /* RR policy */
    qid = (host->requests++ % host->nr_ioqueues) + 1;
    queue = host->ioqueues + qid;
    nvmf_req_co_init(host, &req);
    req.qid = qid;

retry:
    switch (op) {
    case NvmfOpRead:
        req.req = nvmf_read_async(host->ctrl, qid, qiov->iov, qiov->niov,
                                  offset, 0, nvmf_req_cb, &req);
        break;
    case NvmfOpWrite:
        req.req = nvmf_write_async(host->ctrl, qid, qiov->iov, qiov->niov,
                                   offset, 0, nvmf_req_cb, &req);
        break;
    case NvmfOpDiscard:
        req.req = nvmf_discard_async(host->ctrl, qid, &iov, 1, offset, 0,
                                     nvmf_req_cb, &req);
        break;
    case NvmfOpWritezeroes:
        req.req = nvmf_writezeroes_async(host->ctrl, qid, &iov, 1, offset, 0,
                                         nvmf_req_cb, &req);
        break;
    default:
        return -EOPNOTSUPP;
    }

    if (!req.req) {
        /* test queue is full */
        if (nvmf_queue_nr_inflight(host->ctrl, qid) ==
            nvmf_queue_depth(host->ctrl, qid)) {
            qemu_co_mutex_lock(&queue->wait_lock);
            qemu_co_queue_wait(&queue->wait_queue, &queue->wait_lock);
            qemu_co_mutex_unlock(&queue->wait_lock);
            goto retry;
        } else {
            assert(0);
        }
    }

    while (!req.done) {
        qemu_coroutine_yield();
    }

    nvmf_req_free(req.req);

    qemu_co_mutex_lock(&queue->wait_lock);
    if (!qemu_co_queue_empty(&queue->wait_queue)) {
        qemu_co_queue_restart_all(&queue->wait_queue);
    }
    qemu_co_mutex_unlock(&queue->wait_lock);

    return req.retval;
}

static coroutine_fn int nvmf_co_preadv(BlockDriverState *bs, uint64_t offset,
                                       uint64_t bytes, QEMUIOVector *qiov,
                                       int flags)
{
    return nvmf_co_io(bs, offset, bytes, qiov, flags, NvmfOpRead);
}

static coroutine_fn int nvmf_co_pwritev(BlockDriverState *bs, uint64_t offset,
                                        uint64_t bytes, QEMUIOVector *qiov,
                                        int flags)
{
    return nvmf_co_io(bs, offset, bytes, qiov, flags, NvmfOpWrite);
}

static coroutine_fn int nvmf_co_pwrite_zeroes(BlockDriverState *bs,
                                              int64_t offset, int bytes,
                                              BdrvRequestFlags flags)
{
    return nvmf_co_io(bs, offset, bytes, NULL, 0, NvmfOpWritezeroes);
}

static coroutine_fn int nvmf_co_pdiscard(BlockDriverState *bs, int64_t offset,
                                         int bytes)
{
    return nvmf_co_io(bs, offset, bytes, NULL, 0, NvmfOpDiscard);
}

static void nvmf_refresh_limits(BlockDriverState *bs, Error **errp)
{
    NvmfHost *host = bs->opaque;
    unsigned int nsid = nvmf_ns_id(host->ctrl);
    unsigned char lbads = nvmf_ns_lbads(host->ctrl, nsid);

    bs->bl.request_alignment = MAX(BDRV_SECTOR_SIZE, (1 << lbads));
    bs->bl.max_transfer = nvmf_ctrl_mdts(host->ctrl);
    bs->bl.max_iov = nvmf_max_iov(host->ctrl);
}

static int64_t nvmf_getlength(BlockDriverState *bs)
{
    NvmfHost *host = bs->opaque;
    unsigned int nsid = nvmf_ns_id(host->ctrl);
    unsigned char lbads = nvmf_ns_lbads(host->ctrl, nsid);
    unsigned long nsze = nvmf_ns_nsze(host->ctrl, nsid);

    return (1 << lbads) * nsze;
}

static void nvmf_detach_aio_context(BlockDriverState *bs)
{
    NvmfHost *host = bs->opaque;

    qemu_spin_lock(&host->lock);
    aio_set_fd_handler(host->aio_context, nvmf_ctrl_fd(host->ctrl),
                       false, NULL, NULL, NULL, NULL);
    qemu_spin_unlock(&host->lock);
}

static BlockDriver bdrv_nvmf_tcp = {
    .format_name             = "nvmf-tcp",
    .protocol_name           = "nvmf-tcp",
    .instance_size           = sizeof(NvmfHost),
    .bdrv_parse_filename     = nvmf_parse_filename,
    .bdrv_file_open          = nvmf_file_open,
    .bdrv_close              = nvmf_close,
    .bdrv_getlength          = nvmf_getlength,
    .bdrv_refresh_limits     = nvmf_refresh_limits,
    .bdrv_co_pdiscard        = nvmf_co_pdiscard,
    .bdrv_co_preadv          = nvmf_co_preadv,
    .bdrv_co_pwritev         = nvmf_co_pwritev,
    .bdrv_co_pwrite_zeroes   = nvmf_co_pwrite_zeroes,
    .bdrv_detach_aio_context = nvmf_detach_aio_context,
    .bdrv_attach_aio_context = nvmf_attach_aio_context,
};

static BlockDriver bdrv_nvmf_rdma = {
    .format_name             = "nvmf-rdma",
    .protocol_name           = "nvmf-rdma",
    .instance_size           = sizeof(NvmfHost),
    .bdrv_parse_filename     = nvmf_parse_filename,
    .bdrv_file_open          = nvmf_file_open,
    .bdrv_close              = nvmf_close,
    .bdrv_getlength          = nvmf_getlength,
    .bdrv_refresh_limits     = nvmf_refresh_limits,
    .bdrv_co_pdiscard        = nvmf_co_pdiscard,
    .bdrv_co_preadv          = nvmf_co_preadv,
    .bdrv_co_pwritev         = nvmf_co_pwritev,
    .bdrv_co_pwrite_zeroes   = nvmf_co_pwrite_zeroes,
    .bdrv_detach_aio_context = nvmf_detach_aio_context,
    .bdrv_attach_aio_context = nvmf_attach_aio_context,
};

static void nvmf_block_init(void)
{
    bdrv_register(&bdrv_nvmf_tcp);
    bdrv_register(&bdrv_nvmf_rdma);
}

block_init(nvmf_block_init);
