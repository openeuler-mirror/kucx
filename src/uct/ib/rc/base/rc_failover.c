/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#include "rc_iface.h"
#include "rc_ep.h"

#include <uct/api/uct_def.h>
#include <ucs/type/status.h>
#include <uct/ib/base/ib_iface.h>
#include <uct/ib/base/ib_failover.h>
#include <uct/base/uct_iface.h>
#include <ucs/sys/compiler_def.h>
#include <ucs/datastruct/arbiter.h>

void
uct_rc_set_iface_fault_flag(uct_iface_h iface, unsigned status)
{
    uct_ib_iface_t *ib_iface = ucs_derived_of(iface, uct_ib_iface_t);
    uct_ib_set_iface_fault_flag(ib_iface, (uct_dev_fault_status_t)status);
}

/* transfer pending req to new ep */
static void
uct_rc_failover_ep_pending_handle(uct_rc_ep_t *ep, uct_pending_req_t *req, unsigned flags)
{
    uct_rc_iface_t *iface = ucs_derived_of(ep->super.super.iface, uct_rc_iface_t);

    ucs_info("pending transfer req %p to ep %p", req, ep);
    UCS_STATIC_ASSERT(sizeof(uct_pending_req_priv_arb_t) <=
                      UCT_PENDING_REQ_PRIV_LEN);
    uct_pending_req_arb_group_push(&ep->arb_group, req);
    UCT_TL_EP_STAT_PEND(&ep->super);
    ucs_arbiter_group_schedule(&iface->tx.arbiter, &ep->arb_group);
}

static ucs_arbiter_cb_result_t
uct_rc_failover_pending_transfer_cb(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                                    ucs_arbiter_elem_t *elem, void *arg)
{
    uct_rc_ep_t *new_rc_ep = (uct_rc_ep_t *)arg;
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    uct_rc_ep_t *ep = ucs_container_of(group, uct_rc_ep_t, arb_group);
    uct_rc_pending_req_t *freq;

    if (req->func == uct_rc_ep_check_progress) {
        ep->flags &= ~UCT_RC_EP_FLAG_KEEPALIVE_PENDING;
        ucs_mpool_put(req);
    } else if (req->func == uct_rc_ep_fc_grant) {
        freq = ucs_derived_of(req, uct_rc_pending_req_t);
        ucs_mpool_put(freq);
    } else {
        // transfer
        uct_rc_failover_ep_pending_handle(new_rc_ep, req, 0 /* no use */);
    }

    return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
}

ucs_arbiter_cb_result_t
uct_rc_failover_ep_process_pending(ucs_arbiter_t *arbiter,
                                   ucs_arbiter_group_t *group,
                                   ucs_arbiter_elem_t *elem,
                                   void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    uct_rc_ep_t *ep        = ucs_container_of(group, uct_rc_ep_t, arb_group);
    uct_rc_iface_t *iface  = ucs_derived_of(ep->super.super.iface, uct_rc_iface_t);
    ucs_status_t status;

    status = uct_rc_iface_invoke_pending_cb(iface, req);
    if (status == UCS_OK) {
        return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
    } else if (status == UCS_INPROGRESS) {
        return UCS_ARBITER_CB_RESULT_NEXT_GROUP;
    } else if (!uct_rc_iface_has_tx_resources(iface) || status == UCS_ERR_BUSY) {
        /* No iface resources */
        return UCS_ARBITER_CB_RESULT_STOP;
    }

    /* No any other pending operations (except no-op, flush(CANCEL), and others
     * which don't consume TX resources) allowed to be still scheduled on an
     * arbiter group for which flush(CANCEL) was done */
    ucs_assert(!(ep->flags & UCT_RC_EP_FLAG_FLUSH_CANCEL));

    /* No ep resources */
    ucs_assertv(!uct_rc_ep_has_tx_resources(ep),
                "pending callback returned error, but send resources are"
                " available");
    return UCS_ARBITER_CB_RESULT_DESCHED_GROUP;
}

void
uct_rc_ep_failover_pending_transfer_progress(uct_ep_h origin_ep, uct_ep_h new_ep)
{
    uct_rc_ep_t *origin_rc_ep = ucs_derived_of(origin_ep, uct_rc_ep_t);
    uct_rc_ep_t *new_rc_ep = ucs_derived_of(new_ep, uct_rc_ep_t);
    uct_rc_iface_t *origin_rc_iface = ucs_derived_of(origin_rc_ep->super.super.iface, uct_rc_iface_t);
    uct_rc_iface_t *new_rc_iface = ucs_derived_of(new_rc_ep->super.super.iface, uct_rc_iface_t);

    ucs_arbiter_group_purge(&origin_rc_iface->tx.arbiter, &origin_rc_ep->arb_group,
                            uct_rc_failover_pending_transfer_cb, new_rc_ep);
    // try dispatch
    ucs_arbiter_dispatch(&new_rc_iface->tx.arbiter, 1, uct_rc_failover_ep_process_pending, NULL);
}