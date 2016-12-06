/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
* Copyright (c) UT-Battelle, LLC. 2015. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <ucp/core/ucp_mm.h>

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_context.h>
#include <ucp/dt/dt_contig.h>
#include <ucs/debug/profile.h>

#include <ucp/core/ucp_request.inl>
#include <ucs/datastruct/mpool.inl>
#include <ucp/core/ucp_ep.inl>

typedef ucs_status_t 
(*ucp_rma_send_func_t)(ucp_request_t *req, uct_rkey_t uct_rkey, 
                       const ucp_ep_rma_config_t *rma_config);


#define UCP_RMA_CHECK_PARAMS(_buffer, _length) \
    if ((_length) == 0) { \
        return UCS_OK; \
    } \
    if (ENABLE_PARAMS_CHECK && ((_buffer) == NULL)) { \
        return UCS_ERR_INVALID_PARAM; \
    }

/* request can be released if 
 *  - all fragments were sent (length == 0) (bcopy & zcopy mix)
 *  - all zcopy fragments are done (uct_comp.count == 0)
 *  - and request was allocated from the mpool 
 *    (checked in ucp_request_put)
 *
 * Request can be released either immediately or
 * in the completion callback 
 */

static inline ucs_status_t
ucp_rma_request_advance(ucp_request_t *req, size_t frag_length, 
                        ucs_status_t status)
{
    if ((status == UCS_OK) || (status == UCS_INPROGRESS)) {
        req->send.length -= frag_length;
        if (req->send.length == 0) {
            if (req->send.uct_comp.count == 0) {
                ucp_request_put(req, UCS_OK);
            }
            return UCS_OK;
        } 
        req->send.buffer          += frag_length;
        req->send.rma.remote_addr += frag_length;
        return UCS_INPROGRESS;
    } else {
        return status;
    }
}

static void
ucp_rma_request_bcopy_completion(uct_completion_t *self, ucs_status_t status)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct_comp);

    ucp_request_put(req, UCS_OK);
}

static inline ucs_status_t
ucp_rma_request_init(ucp_request_t *req, ucp_ep_h ep, const void *buffer, 
                     size_t length, uint64_t remote_addr, ucp_rkey_h rkey,
                     uct_pending_callback_t cb, ucp_lane_index_t lane,
                     int flags)
{
    req->flags                = flags; /* Implicit release */
    req->send.ep              = ep;
    req->send.buffer          = buffer;
    req->send.length          = length;
    req->send.rma.remote_addr = remote_addr;
    req->send.rma.rkey        = rkey;
    req->send.uct.func        = cb;
    req->send.lane            = lane;
    req->send.uct_comp.count  = 0; 
    req->send.uct_comp.func   = ucp_rma_request_bcopy_completion;

#if ENABLE_ASSERT
    req->send.cb              = NULL;
#endif
    return UCS_OK;
}

static inline ucs_status_t 
ucp_progress_put_inner(ucp_request_t *req, uct_rkey_t uct_rkey, 
                       const ucp_ep_rma_config_t *rma_config)
{
    ucp_ep_t *ep = req->send.ep;
    ucs_status_t status;
    ssize_t packed_len;

    if (req->send.length <= ucp_ep_config(ep)->bcopy_thresh) {
        packed_len = ucs_min(req->send.length, rma_config->max_put_short);
        status = UCS_PROFILE_CALL(uct_ep_put_short,
                                  ep->uct_eps[req->send.lane],
                                  req->send.buffer,
                                  packed_len,
                                  req->send.rma.remote_addr,
                                  uct_rkey);
    } else {
        ucp_memcpy_pack_context_t pack_ctx;
        pack_ctx.src    = req->send.buffer;
        pack_ctx.length = ucs_min(req->send.length, rma_config->max_put_bcopy);
        packed_len = UCS_PROFILE_CALL(uct_ep_put_bcopy,
                                      ep->uct_eps[req->send.lane],
                                      ucp_memcpy_pack,
                                      &pack_ctx,
                                      req->send.rma.remote_addr,
                                      uct_rkey);
        status = (packed_len > 0) ? UCS_OK : (ucs_status_t)packed_len;
    }

    return ucp_rma_request_advance(req, packed_len, status);    
}

static ucs_status_t 
ucp_progress_get_inner(ucp_request_t *req, uct_rkey_t uct_rkey, 
                       const ucp_ep_rma_config_t *rma_config)
{
    ucp_ep_t *ep = req->send.ep;
    ucs_status_t status;
    size_t frag_length;

    ++req->send.uct_comp.count;
    frag_length = ucs_min(rma_config->max_get_bcopy, req->send.length);
    status = UCS_PROFILE_CALL(uct_ep_get_bcopy,
                              ep->uct_eps[req->send.lane],
                              (uct_unpack_callback_t)memcpy,
                              (void*)req->send.buffer,
                              frag_length,
                              req->send.rma.remote_addr,
                              uct_rkey,
                              &req->send.uct_comp);
    if (status <= 0) {
        --req->send.uct_comp.count;
    }

    return ucp_rma_request_advance(req, frag_length, status);    
}

static ucs_status_t ucp_progress_get_nbi(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    ucp_rkey_h rkey    = req->send.rma.rkey;
    ucp_ep_t *ep       = req->send.ep;

    uct_rkey_t uct_rkey;
    ucp_ep_rma_config_t *rma_config;


    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, req->send.lane, uct_rkey, rma_config);
    return ucp_progress_get_inner(req, uct_rkey, rma_config);
}

static ucs_status_t ucp_progress_put_nbi(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    ucp_rkey_h rkey    = req->send.rma.rkey;
    ucp_ep_t *ep       = req->send.ep;

    uct_rkey_t uct_rkey;
    ucp_ep_rma_config_t *rma_config;


    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, req->send.lane, uct_rkey, rma_config);
    return ucp_progress_put_inner(req, uct_rkey, rma_config);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rma_blocking(ucp_ep_h ep, const void *buffer, size_t length, uint64_t remote_addr, 
                 ucp_rkey_h rkey, ucp_ep_rma_config_t *rma_config, 
                 ucp_lane_index_t lane, uct_rkey_t uct_rkey,
                 ucp_rma_send_func_t send_func)
{
    ucs_status_t status;
    ucp_request_t req;

    ucs_assert((send_func == ucp_progress_put_inner) ||
               (send_func == ucp_progress_get_inner));

    status = ucp_rma_request_init(&req, ep, buffer, length, remote_addr, rkey,
                                  NULL, lane, 0);
    if (status != UCS_OK) {
        return status;
    }

    /* Loop until all message has been sent.
     * We re-check the configuration on every iteration except for zcopy, 
     * because it can be * changed by transport switch.
     */
    for (;;) {
        status = send_func(&req, uct_rkey, rma_config);
        if (ucs_likely(status == UCS_OK)) {
            break;
        } else if (status == UCS_INPROGRESS) {
            continue;
        } else if (status != UCS_ERR_NO_RESOURCE) {
            break;
        } else {
            ucp_worker_progress(ep->worker);
            UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, req.send.lane, uct_rkey, rma_config);
        }
    }

    ucp_request_wait_uct_comp(&req);
    return status;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rma_nbi(ucp_ep_h ep, const void *buffer, size_t length, uint64_t remote_addr, 
            ucp_rkey_h rkey, ucp_ep_rma_config_t *rma_config,
            ucp_lane_index_t lane, uct_rkey_t uct_rkey,
            ucp_rma_send_func_t send_func)
{
    ucs_status_t status;
    ucp_request_t *req;

    ucs_assert((send_func == ucp_progress_put_inner) ||
               (send_func == ucp_progress_get_inner));

    req = ucp_request_get(ep->worker);
    if (req == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    ucp_rma_request_init(req, ep, buffer, length, remote_addr, rkey, 
                         send_func == ucp_progress_put_inner ? 
                          ucp_progress_put_nbi : ucp_progress_get_nbi, 
                         lane, UCP_REQUEST_FLAG_RELEASED);
    /* Start send using inner progress function in order to avoid
     * extra RKEY lookup
     */
    do {
        status = send_func(req, uct_rkey, rma_config);
        if (status == UCS_ERR_NO_RESOURCE) {
            if (ucp_request_pending_add(req, &status)) {
                return status;
            }
        } else if (status < 0) {
            return status;
        } else {
            if (status != UCS_INPROGRESS) {
                return status;
            }
        }
    } while (1);
}

ucs_status_t ucp_put_nbi(ucp_ep_h ep, const void *buffer, size_t length,
                         uint64_t remote_addr, ucp_rkey_h rkey)
{
    ucp_ep_rma_config_t *rma_config;
    ucp_lane_index_t lane;
    uct_rkey_t uct_rkey;
    ucs_status_t status;

    UCP_RMA_CHECK_PARAMS(buffer, length);
    UCP_THREAD_CS_ENTER_CONDITIONAL(&ep->worker->mt_lock);
    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, lane, uct_rkey, rma_config);

    /* Fast path for a single short message */
    if (length <= rma_config->max_put_short) {
        status = UCS_PROFILE_CALL(uct_ep_put_short, ep->uct_eps[lane], buffer, 
                                  length, remote_addr, uct_rkey);
        if (ucs_likely(status != UCS_ERR_NO_RESOURCE)) {
            goto out;
        }
    }

    status = ucp_rma_nbi(ep, buffer, length, remote_addr, rkey, 
                         rma_config, lane, uct_rkey, 
                         ucp_progress_put_inner);
out:
    UCP_THREAD_CS_EXIT_CONDITIONAL(&ep->worker->mt_lock);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_put, (ep, buffer, length, remote_addr, rkey),
                 ucp_ep_h ep, const void *buffer, size_t length,
                 uint64_t remote_addr, ucp_rkey_h rkey)
{
    ucp_ep_rma_config_t *rma_config;
    ucs_status_t status;
    uct_rkey_t uct_rkey;
    ucp_lane_index_t lane;

    UCP_RMA_CHECK_PARAMS(buffer, length);
    UCP_THREAD_CS_ENTER_CONDITIONAL(&ep->worker->mt_lock);
    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, lane, uct_rkey, rma_config);

    if (length <= rma_config->max_put_short) {
        status = UCS_PROFILE_CALL(uct_ep_put_short, ep->uct_eps[lane], buffer,
                                  length, remote_addr, uct_rkey);
        if (ucs_likely(status != UCS_ERR_NO_RESOURCE)) {
            goto out;
        }
    }

    status = ucp_rma_blocking(ep, buffer, length, remote_addr, rkey, 
                              rma_config, lane, uct_rkey, 
                              ucp_progress_put_inner);
out:
    UCP_THREAD_CS_EXIT_CONDITIONAL(&ep->worker->mt_lock);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_get, (ep, buffer, length, remote_addr, rkey),
                 ucp_ep_h ep, void *buffer, size_t length,
                 uint64_t remote_addr, ucp_rkey_h rkey)
{
    ucp_ep_rma_config_t *rma_config;
    uct_rkey_t uct_rkey;
    ucp_lane_index_t lane;
    ucs_status_t status;

    UCP_RMA_CHECK_PARAMS(buffer, length);
    UCP_THREAD_CS_ENTER_CONDITIONAL(&ep->worker->mt_lock);
    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, lane, uct_rkey, rma_config);

    status = ucp_rma_blocking(ep, buffer, length, remote_addr, rkey, 
                              rma_config, lane, uct_rkey, 
                              ucp_progress_get_inner);

    UCP_THREAD_CS_EXIT_CONDITIONAL(&ep->worker->mt_lock);
    return status;
}

ucs_status_t ucp_get_nbi(ucp_ep_h ep, void *buffer, size_t length,
                         uint64_t remote_addr, ucp_rkey_h rkey)
{
    ucp_ep_rma_config_t *rma_config;
    uct_rkey_t uct_rkey;
    ucp_lane_index_t lane;
    ucs_status_t status;

    UCP_RMA_CHECK_PARAMS(buffer, length);
    UCP_THREAD_CS_ENTER_CONDITIONAL(&ep->worker->mt_lock);
    UCP_EP_RESOLVE_RKEY_RMA(ep, rkey, lane, uct_rkey, rma_config);

    status = ucp_rma_nbi(ep, buffer, length, remote_addr, rkey, 
                         rma_config, lane, uct_rkey, 
                         ucp_progress_get_inner);

    UCP_THREAD_CS_EXIT_CONDITIONAL(&ep->worker->mt_lock);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_worker_fence, (worker), ucp_worker_h worker)
{
    unsigned rsc_index;
    ucs_status_t status;

    UCP_THREAD_CS_ENTER_CONDITIONAL(&worker->mt_lock);

    for (rsc_index = 0; rsc_index < worker->context->num_tls; ++rsc_index) {
        if (worker->ifaces[rsc_index] == NULL) {
            continue;
        }

        status = uct_iface_fence(worker->ifaces[rsc_index], 0);
        if (status != UCS_OK) {
            goto out;
        }
    }
    status = UCS_OK;

out:
    UCP_THREAD_CS_EXIT_CONDITIONAL(&worker->mt_lock);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_worker_flush, (worker), ucp_worker_h worker)
{
    unsigned rsc_index;

    UCP_THREAD_CS_ENTER_CONDITIONAL(&worker->mt_lock);

    while (worker->stub_pend_count > 0) {
        ucp_worker_progress(worker);
    }

    /* TODO flush in parallel */
    for (rsc_index = 0; rsc_index < worker->context->num_tls; ++rsc_index) {
        if (worker->ifaces[rsc_index] == NULL) {
            continue;
        }

        while (uct_iface_flush(worker->ifaces[rsc_index], 0, NULL) != UCS_OK) {
            ucp_worker_progress(worker);
        }
    }

    UCP_THREAD_CS_EXIT_CONDITIONAL(&worker->mt_lock);

    return UCS_OK;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_ep_flush, (ep), ucp_ep_h ep)
{
    ucp_lane_index_t lane;
    ucs_status_t status;

    UCP_THREAD_CS_ENTER_CONDITIONAL(&ep->worker->mt_lock);

    for (lane = 0; lane < ucp_ep_num_lanes(ep); ++lane) {
        for (;;) {
            status = uct_ep_flush(ep->uct_eps[lane], 0, NULL);
            if (status == UCS_OK) {
                break;
            } else if ((status != UCS_INPROGRESS) && (status != UCS_ERR_NO_RESOURCE)) {
                goto out;
            }
            ucp_worker_progress(ep->worker);
        }
    }

    status = UCS_OK;
out:
    UCP_THREAD_CS_EXIT_CONDITIONAL(&ep->worker->mt_lock);
    return status;
}

