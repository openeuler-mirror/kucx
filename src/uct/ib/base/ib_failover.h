/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#ifndef UCT_IB_FAILOVER_H
#define UCT_IB_FAILOVER_H

#include <ucs/type/status.h>
#include <uct/api/uct_def.h>

#include "ib_iface.h"
#include "ib_device.h"

#define FO_MAX_IOV      16      // ref UCP_MAX_IOV

typedef struct zcopy_resend_comp {
    uct_completion_t    uct_comp;
    uct_md_h            md;
    uct_mem_h           memh[FO_MAX_IOV];
    uint16_t            memh_num;
    uct_completion_t    *origin_uct_comp;
} zcopy_resend_comp_t;

void uct_ib_resend_zcopy_completion_cb(uct_completion_t *self);

void uct_ib_iface_failure_handle(uct_ib_iface_t *ib_iface);

ucs_status_t uct_ep_failure_handle(uct_ep_t *uct_ep);

/**
 * Check dev fault or not according to async-event
 *
 * @param [in]  event   ib async event.
 * @return  1 means need, 0 means not.
 */
int uct_ib_dev_event_check_fault(uct_ib_async_event_t *event);

uint64_t uct_ib_iface_get_device_guid(uct_iface_h iface);

static inline uct_dev_fault_status_t uct_ib_check_iface_fault_flag(uct_ib_iface_t *ib_iface)
{
    return uct_ib_iface_device(ib_iface)->fault_flag;
}

static inline void uct_ib_set_iface_fault_flag(uct_ib_iface_t *ib_iface, uct_dev_fault_status_t status)
{
    ucs_info("set iface %p status %u", ib_iface, status);
    uct_ib_iface_device(ib_iface)->fault_flag = status;
}

/**
 * Unpack IB address.
 *
 * @param [in]  wc   ibv_wc when poll txcq or rxcq.
 * @return  need failover or not, 1 means need, 0 means not.
 */
int uct_ib_poll_cq_wr_status_need_failover(struct ibv_wc *wc);

#endif