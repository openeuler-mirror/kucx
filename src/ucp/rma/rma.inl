/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RMA_INL_
#define UCP_RMA_INL_

#include <ucp/api/ucp.h>
#include <ucp/core/ucp_request.h>
#include <ucp/core/ucp_request.inl>
#include <ucs/debug/log.h>


static UCS_F_ALWAYS_INLINE ucs_status_ptr_t
ucp_rma_send_request_cb(ucp_request_t *req, ucp_send_callback_t cb)
{
    ucs_status_t status = ucp_request_send(req);

    if (req->flags & UCP_REQUEST_FLAG_COMPLETED) {
        ucs_trace_req("releasing send request %p, returning status %s", req,
                      ucs_status_string(status));
        ucs_mpool_put(req);
        return UCS_STATUS_PTR(status);
    }

    ucs_trace_req("returning request %p, status %s", req,
                  ucs_status_string(status));
    ucp_request_set_callback(req, send.cb, cb);
    return req + 1;
}

static inline ucs_status_t ucp_rma_wait(ucp_worker_h worker, void *user_req,
                                        const char *op_name)
{
    ucs_status_t status;
    ucp_request_t *req;

    if (ucs_likely(user_req == NULL)) {
        return UCS_OK;
    } else if (ucs_unlikely(UCS_PTR_IS_ERR(user_req))) {
        ucs_warn("%s failed: %s", op_name,
                 ucs_status_string(UCS_PTR_STATUS(user_req)));
        return UCS_PTR_STATUS(user_req);
    } else {
        req = (ucp_request_t*)user_req - 1;
        do {
            ucp_worker_progress(worker);
            status = ucp_request_check_status(user_req);
        } while (!(req->flags & UCP_REQUEST_FLAG_COMPLETED));
        status = req->status;
        ucp_request_release(user_req);
        return status;
    }
}

#endif
