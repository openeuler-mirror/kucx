/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#include <uct/api/uct_def.h>
#include <uct/api/uct.h>
#include <ucs/type/status.h>
#include <ucs/async/async.h>
#include <ucs/debug/log_def.h>

#include "ib_device.h"
#include "ib_iface.h"
#include "ib_failover.h"

// get ib device unique global uid
uint64_t uct_ib_iface_get_device_guid(uct_iface_h iface)
{
    uct_ib_iface_t *ib_iface = ucs_derived_of(iface, uct_ib_iface_t);
    uct_ib_device_t *dev = uct_ib_iface_device(ib_iface);
    return ibv_get_device_guid(dev->ibv_context->device);
}

static unsigned uct_ib_iface_failure_handle_progress(void *args)
{
    uct_ib_iface_t *ib_iface = (uct_ib_iface_t *)args;
    uct_worker_h worker = (uct_worker_h)ib_iface->super.worker;
    ucs_status_t status;
    ucs_info("starting failover iface %p!", ib_iface);
    UCS_ASYNC_BLOCK(ib_iface->super.worker->async);
    status = ib_iface->failover.ops.failover_upcall(ib_iface->failover.err_handler_arg, &ib_iface->super.super);
    if (status != UCS_OK) {
        UCS_ASYNC_UNBLOCK(ib_iface->super.worker->async);
        return 0;
    }

    uct_ib_set_iface_fault_flag(ib_iface, DEV_FO_FLAG_MIGRATING);
    uct_worker_progress_unregister_safe(worker, &ib_iface->failover.failover_prog_id);
    UCS_ASYNC_UNBLOCK(ib_iface->super.worker->async);
    return 1;
}

// lock protected
void uct_ib_iface_failure_handle(uct_ib_iface_t *ib_iface)
{
    uct_worker_h worker = (uct_worker_h)ib_iface->super.worker;
    uct_worker_progress_register_safe(worker, uct_ib_iface_failure_handle_progress,
        ib_iface, UCS_CALLBACKQ_FLAG_FAST, &ib_iface->failover.failover_prog_id);
    return;
}

// lock protected, already in progress
ucs_status_t uct_ep_failure_handle(uct_ep_h uct_ep)
{
    uct_ib_iface_t *ib_iface = ucs_derived_of(uct_ep->iface, uct_ib_iface_t);
    ucs_status_t status = UCS_OK;
    if (ib_iface->failover.ops.ep_failover_upcall) {
        status = ib_iface->failover.ops.ep_failover_upcall(ib_iface->failover.err_handler_arg, uct_ep);
    }
    return status;
}

int uct_ib_dev_event_check_fault(uct_ib_async_event_t *event)
{
    int ret = 0;
    switch (event->event_type) {
    case IBV_EVENT_QP_FATAL:
    case IBV_EVENT_PATH_MIG_ERR:
    case IBV_EVENT_PORT_ERR:
    case IBV_EVENT_DEVICE_FATAL:
        ret = 1;
        break;
    default:
        break;
    }
    return ret;
}

int uct_ib_poll_cq_wr_status_need_failover(struct ibv_wc *wc)
{
    if (wc->status == IBV_WC_WR_FLUSH_ERR ||
        wc->status == IBV_WC_REM_OP_ERR ||
        wc->status == IBV_WC_RETRY_EXC_ERR ||   /* if peer-end fault, local-end will detect it */
        wc->status == IBV_WC_REM_ABORT_ERR ||
        wc->status == IBV_WC_FATAL_ERR ||
        wc->status == IBV_WC_RESP_TIMEOUT_ERR) {
        return 1;
    }
    return 0;
}

// zcopy callback, here we need to unreg memh and free comp
void uct_ib_resend_zcopy_completion_cb(uct_completion_t *self)
{
    zcopy_resend_comp_t *comp = (zcopy_resend_comp_t *)self;
    uint16_t i;
    for (i = 0; i < comp->memh_num; i++) {
        if (comp->memh[i]) {
            uct_md_mem_dereg(comp->md, comp->memh[i]);
        }
    }
    if (comp->origin_uct_comp) {
        comp->origin_uct_comp->count--;
        if (comp->origin_uct_comp->count == 0) {
            comp->origin_uct_comp->func(comp->origin_uct_comp);
        }
    }
    ucs_free(comp);
    return;
}
