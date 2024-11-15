/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#include <ucs/debug/memtrack_int.h>
#include <uct/api/uct.h>
#include <ucs/debug/log_def.h>
#include <ucp/wireup/wireup_ep.h>

#include "ucp_types.h"
#include "ucp_failover.h"
#include "ucp_ep.h"
#include "ucp_ep.inl"

#define UCP_FAILOVER_DEAULT_TIMEOUT 120      // s

typedef enum {
    META_MSG_TYPE_REQ           = 1,
    META_MSG_TYPE_RESP          = 2,
    META_MSG_TYPE_RESP_REVICE   = 3
} ucp_failover_meta_msg_type_t;

/* ucp failover info for am exchange, so it should not be larger */
typedef struct ucp_failover_info {
    /* uniq id. if different lanes are selected on both sides, guid is used for decision-making */
    uint64_t guid;

    /* local faulty lane */
    ucp_lane_index_t origin_lane;

    /* remote faulty lane */
    ucp_lane_index_t remote_origin_lane;

    /* local new lane */
    ucp_lane_index_t new_lane;

    /* remote new lane */
    ucp_lane_index_t remote_new_lane;

    /* record lane type, ref lane_type_t */
    uint32_t lane_type;

    /* private data to save peer ack, for resending */
    uint64_t private_data;

    /* msg type */
    uint32_t msg_type;
} ucp_failover_info_t;

typedef enum {
    /* request rkey */
    MSG_TYPE_GET_RKEY,

    /* response rkey */
    MSG_TYPE_RESP_RKEY,

    /* release rkey */
    MSG_TYPE_RELEASE_RKEY
} ucp_rkey_msg_type_t;

typedef struct ucp_rkey_handle {
    /* ucp_rkey_msg_type_t */
    uint8_t msg_type;

    /* local faulty lane */
    uint8_t origin_lane;

    /* remote faulty lane */
    uint8_t remote_new_lane;

    /* one-side addr to get rkey */
    uint64_t addr;

    /* one-side addr length to get rkey */
    uint64_t length;

    /* one-side addr rkey */
    uint64_t rkey;

    /* one-side addr memh for release rkey */
    uint64_t memh;
} ucp_rkey_handle_t;

typedef struct ucp_handle_info {
    ucp_ep_h ucp_ep;
    uct_iface_h iface;
    uct_worker_cb_id_t progress_id;
} ucp_handle_info_t;

/* we cache lanes2remote in ep, so here we can get remote_lane directly */
static inline ucp_lane_index_t
ucp_failover_get_remote_lane(ucp_ep_h ucp_ep, ucp_lane_index_t lane)
{
    if (ucs_unlikely(lane >= UCP_MAX_LANES || lane == UCP_NULL_LANE)) {
        ucs_fatal("get remote lane exception, ucp_ep %p lane %d", ucp_ep, lane);
    }
    return (ucp_ep->lanes2remote[lane] == UCP_NULL_LANE) ? lane : ucp_ep->lanes2remote[lane];
}

/*
 * because of wireup ep exists, we cannot get bottom ep directly
 * extra judgment is required when getting ep.
 */
static uct_ep_h
ucp_ep_failover_get_lane(ucp_ep_h ucp_ep, ucp_lane_index_t lane_index)
{
    ucp_wireup_ep_t *wireup_ep;
    uct_ep_h ep = ucp_ep_get_lane(ucp_ep, lane_index);
    if (ucs_unlikely(!ep)) {
        ucs_debug("no such ep, ucp_ep %p lane %d", ucp_ep, lane_index);
        return ep;
    }
    /* test whether ep belongs to wireup_ep */
    if (!ucp_wireup_ep_test(ep)) {
        return ep;
    }
    wireup_ep = ucp_wireup_ep(ep);
    return wireup_ep->super.uct_ep;
}

/* init ep failover context */
static ucs_status_t
ucp_ep_create_fo_ctx(ucp_ep_h ep, ucp_lane_index_t origin_lane, lane_type_t lane_type,
                     lane_fault_type_t lane_fault_type)
{
    failover_ctx_t *ctx = NULL;
    if (origin_lane >= UCP_MAX_LANES) {
        ucs_error("Fail to create fo ctx, because lane index(%u) out of bond", origin_lane);
        return UCS_ERR_INVALID_PARAM;
    }
    if (ep->failover_ctx.failover_array[origin_lane]) {
        ucs_info("another fo ctx in progress, origin lane(%u)", origin_lane);
    } else {
        ctx = ucs_calloc(1, sizeof(failover_ctx_t), "fo ctx");
        if (!ctx) {
            ucs_error("Fail to create fo ctx, because no memory, origin lane(%u)", origin_lane);
            return UCS_ERR_NO_MEMORY;
        }
        ctx->origin_lane = origin_lane;
        ctx->remote_origin_lane = ucp_failover_get_remote_lane(ep, origin_lane);
        ctx->lane_type = lane_type;
        ctx->lane_fault_type = lane_fault_type;
        ctx->cycle_time = ucs_get_time();
        ep->failover_ctx.failover_array[origin_lane] = ctx;
        ep->failover_ctx.failover_array[origin_lane]->state |= UCP_FO_FLAG_INIT;
        ep->failover_ctx.failover_num++;
    }
    return UCS_OK;
}

/* release ep failover context */
static void
ucp_ep_free_fo_ctx(ucp_ep_h ep, ucp_lane_index_t origin_lane)
{
    if (origin_lane >= UCP_MAX_LANES) {
        ucs_error("Fail to free fo ctx, because lane index(%u) out of bond", origin_lane);
        return;
    }
    if (ep->failover_ctx.failover_array[origin_lane]) {
        ucs_free(ep->failover_ctx.failover_array[origin_lane]);
        ep->failover_ctx.failover_array[origin_lane] = NULL;
        ep->failover_ctx.failover_num--;
    }
    return;
}

// reselect logic
static ucs_status_t
ucp_failover_reselect(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucp_worker_iface_t *wiface;
    ucp_rsc_index_t rsc_index;
    uint8_t i;
    /* we need to reselect from current key config */
    for (i = 0; i < ucp_ep_config(ucp_ep)->key.num_lanes; i++) {
        if (fo_ctx->origin_lane == i) {     // skip self
            continue;
        }

        if (UCS_BITMAP_GET(ucp_ep->discarded_lane_bitmap, i)) {  // already discard
            continue;
        }

        rsc_index = ucp_ep_config(ucp_ep)->key.lanes[i].rsc_index;
        if (UCS_BITMAP_GET(ucp_ep->discarded_rsc_bitmap, rsc_index)) {  // already discard
            continue;
        }

        wiface = ucp_worker_iface(ucp_ep->worker, rsc_index);
        if (!wiface->iface->ops.ep_resend) {
            /* skip unsupported lane */
            continue;
        }
        /* min requirement of the lane we choose need to support am */
        if (wiface->attr.cap.flags & UCT_IFACE_FLAG_AM_SHORT) {
            fo_ctx->new_lane = i;
            fo_ctx->remote_new_lane = ucp_failover_get_remote_lane(ucp_ep, i);
        } else {
            continue;
        }

        return UCS_OK;
    }
    return UCS_ERR_NO_RESOURCE;
}

static inline uint64_t
ucp_get_device_guid(uct_ep_h uct_ep)
{
    if (uct_ep->iface->ops.iface_get_device_guid) {
        return uct_ep->iface->ops.iface_get_device_guid(uct_ep->iface);
    }
    return (uint64_t)-1;
}

static inline uint64_t
ucp_get_ep_private_data(uct_ep_h uct_ep)
{
    uint64_t private_data = 0;
    if (uct_ep->iface->ops.ep_get_private_date) {
        /* maybe we don't care this return value */
        (void)uct_ep->iface->ops.ep_get_private_date(uct_ep, &private_data);
    }

    return private_data;
}

static ucs_status_t
ucp_failover_pre_handle(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->origin_lane);
    ucs_status_t ret = UCS_OK;
    if (origin_ep->iface->ops.ep_pre_handle) {
        ret = origin_ep->iface->ops.ep_pre_handle(origin_ep);
    }
    return ret;
}

static ucs_status_t
ucp_failover_send_meta(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx, int is_reply)
{
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->origin_lane);
    uct_ep_h comm_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->new_lane);
    /*
     * before we send meta, we must get remote ep id first
     * see ucp_failover_progress_resolved_epid
     */
    uint64_t remote_id = (uint64_t)ucp_ep_remote_id(ucp_ep);
    ucp_failover_info_t info;

    fo_ctx->guid = ucp_get_device_guid(origin_ep);
    info.guid = fo_ctx->guid;
    info.origin_lane = fo_ctx->origin_lane;
    info.remote_origin_lane = fo_ctx->remote_origin_lane;
    info.new_lane = fo_ctx->new_lane;
    info.remote_new_lane = fo_ctx->remote_new_lane;
    info.lane_type = fo_ctx->lane_type;
    info.private_data = ucp_get_ep_private_data(origin_ep);
    info.msg_type = is_reply ? META_MSG_TYPE_RESP : META_MSG_TYPE_REQ;
    ucs_info("ep %p is_reply %d, private data %lu, lane_type %u, origin_ep %p, comm_ep %p",
             ucp_ep, is_reply, info.private_data, info.lane_type, origin_ep, comm_ep);

    return uct_ep_am_short(comm_ep, UCP_AM_ID_FAILOVER_HANDLER, remote_id, &info, sizeof(ucp_failover_info_t));
}

static ucs_status_t
ucp_failover_get_rkey(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uct_ep_h comm_ep;
    uint64_t remote_id;
    ucs_status_t ret;
    ucp_rkey_handle_t req;

    if (!(fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_INIT)) {
        return UCS_OK;  // no need to get rkey
    }

    if (fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_REQ_SENT) {
        return UCS_OK;  // already in progress
    }

    comm_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->new_lane);
    /*
     * before we get rkey, we must get remote ep id first
     * see ucp_failover_progress_resolved_epid
     */
    remote_id = (uint64_t)ucp_ep_remote_id(ucp_ep);

    req.msg_type = MSG_TYPE_GET_RKEY;
    req.origin_lane = fo_ctx->origin_lane;
    req.remote_new_lane = fo_ctx->remote_new_lane;
    req.addr = fo_ctx->rkey_ctx.addr;
    req.length = fo_ctx->rkey_ctx.length;
    req.memh = 0;

    ret = uct_ep_am_short(comm_ep, UCP_AM_ID_RKEY_HANDLER, remote_id, &req, sizeof(req));
    if (ret != UCS_OK) {
        ucs_error("send get rkey failed %d", ret);
        return ret;
    }
    fo_ctx->rkey_ctx.rkey_state |= UCT_RKEY_REQ_SENT;
    ucs_info("send rkey req %p %lu", (void *)req.addr, req.length);
    return UCS_OK;
}

static ucs_status_t
ucp_failover_release_rkey(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uct_ep_h comm_ep;
    uint64_t remote_id;
    ucs_status_t ret;
    ucp_rkey_handle_t req = {0};

    if (!(fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_USED)) {
        return UCS_OK;
    }

    if (ucs_unlikely(!fo_ctx->rkey_ctx.memh)) {
        return UCS_OK;
    }

    comm_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->new_lane);
    remote_id = (uint64_t)ucp_ep_remote_id(ucp_ep);

    req.msg_type = MSG_TYPE_RELEASE_RKEY;
    req.remote_new_lane = fo_ctx->remote_new_lane;
    req.memh = fo_ctx->rkey_ctx.memh;

    ret = uct_ep_am_short(comm_ep, UCP_AM_ID_RKEY_HANDLER, remote_id, &req, sizeof(req));
    if (ret != UCS_OK) {
        ucs_error("send release rkey failed %d", ret);
        if (ret == UCS_ERR_BUSY) {
            fo_ctx->rkey_ctx.rkey_state = UCT_RKEY_RELEASED;
            return UCS_OK;  /* we dont care about BUSY error, because of ep fault */
        }
        return ret;
    }

    fo_ctx->rkey_ctx.rkey_state = UCT_RKEY_RELEASED;        // reset
    ucs_info("send rkey release memh %p", (void *)(req.memh));
    return UCS_OK;
}

/* exchange some data from two wireup ep */
static void
ucp_failover_exchange_wireup_aux(ucp_wireup_ep_t *wireup_ep, ucp_wireup_ep_t *origin_wireup_ep)
{
    ucp_wireup_ep_t tmp_wireup_ep;
    memcpy((void *)(&tmp_wireup_ep.wireup_fo_ext), (void *)(&origin_wireup_ep->wireup_fo_ext),
            sizeof(ucp_wireup_failover_ext_t));
    memcpy((void *)(&origin_wireup_ep->wireup_fo_ext), (void *)(&wireup_ep->wireup_fo_ext),
            sizeof(ucp_wireup_failover_ext_t));
    memcpy((void *)(&wireup_ep->wireup_fo_ext), (void *)(&tmp_wireup_ep.wireup_fo_ext),
            sizeof(ucp_wireup_failover_ext_t));

    tmp_wireup_ep.aux_ep = origin_wireup_ep->aux_ep;
    origin_wireup_ep->aux_ep = wireup_ep->aux_ep;
    wireup_ep->aux_ep = tmp_wireup_ep.aux_ep;

    tmp_wireup_ep.aux_rsc_index = origin_wireup_ep->aux_rsc_index;
    origin_wireup_ep->aux_rsc_index = wireup_ep->aux_rsc_index;
    wireup_ep->aux_rsc_index = tmp_wireup_ep.aux_rsc_index;

    tmp_wireup_ep.flags = origin_wireup_ep->flags;
    origin_wireup_ep->flags = wireup_ep->flags;
    wireup_ep->flags = tmp_wireup_ep.flags;

    tmp_wireup_ep.ep_init_flags = origin_wireup_ep->ep_init_flags;
    origin_wireup_ep->ep_init_flags = wireup_ep->ep_init_flags;
    wireup_ep->ep_init_flags = tmp_wireup_ep.ep_init_flags;
    return;
}

static ucs_status_t
ucp_failover_change_wireup_lane(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucp_worker_h worker = ucp_ep->worker;
    ucp_ep_config_key_t failover_key;
    ucp_worker_cfg_index_t new_cfg_index;
    ucp_wireup_ep_t *wireup_ep;
    ucp_wireup_ep_t *origin_wireup_ep;
    ucs_status_t status;
    UCS_ASYNC_BLOCK(&worker->async);

    /* check if need to change */
    if (ucp_ep_config(ucp_ep)->key.wireup_msg_lane != fo_ctx->origin_lane) {
        UCS_ASYNC_UNBLOCK(&worker->async);
        return UCS_OK;
    }
    /* need alloc a new config_key to avoid conflict */
    memcpy(&failover_key, &ucp_ep_config(ucp_ep)->key, sizeof(ucp_ep_config_key_t));
    failover_key.wireup_msg_lane = fo_ctx->new_lane;
    status = ucp_worker_get_ep_config(worker, &failover_key, UCP_EP_INIT_RESELECE_WIREUP, &new_cfg_index);
    if (status != UCS_OK) {
        UCS_ASYNC_UNBLOCK(&worker->async);
        ucs_error("ep: %p failover get config error when change wireup, ret: %d", ucp_ep, status);
        return status;
    }
    ucp_ep->cfg_index = new_cfg_index;
    ucs_info("ep %p change wireup to %u config id %u", ucp_ep, ucp_ep_config(ucp_ep)->key.wireup_msg_lane, ucp_ep->cfg_index);

    /* check if need to exchange */
    wireup_ep = ucp_wireup_ep(ucp_ep_get_lane(ucp_ep, failover_key.wireup_msg_lane));
    if (wireup_ep) {
        origin_wireup_ep = ucp_wireup_ep(ucp_ep_get_lane(ucp_ep, fo_ctx->origin_lane));
        if (origin_wireup_ep) {
            /* exchange wireup ep */
            ucp_failover_exchange_wireup_aux(wireup_ep, origin_wireup_ep);
            ucs_info("ep %p exchange wireup %u <=> %u", ucp_ep, fo_ctx->origin_lane, failover_key.wireup_msg_lane);
        }
    } 

    UCS_ASYNC_UNBLOCK(&worker->async);
    return UCS_OK;
}

// Search for the iface in the worker ifaces based on rsc_index in the ep_config_key.
static uct_iface_h
ucp_ep_get_iface_from_lane(ucp_ep_h ucp_ep, ucp_lane_index_t lane)
{
    ucp_rsc_index_t rsc_index;
    ucp_worker_iface_t *wiface;
    if (ucs_unlikely(lane == UCP_NULL_LANE)) {
        return NULL;
    }
    rsc_index = ucp_ep_config(ucp_ep)->key.lanes[lane].rsc_index;
    wiface = ucp_worker_iface(ucp_ep->worker, rsc_index);
    return wiface->iface;
}

static ucs_status_t
ucp_failover_copy_ep_config_md_cmpts(ucp_ep_config_key_t *failover_key, ucp_ep_config_key_t *origin_key)
{
    int num_md_cmpts;
    ucp_rsc_index_t *md_cmpts;

    num_md_cmpts = ucs_popcount(origin_key->reachable_md_map);
    if (num_md_cmpts == 0) {
        md_cmpts = NULL;
        goto out;
    }

    md_cmpts = ucs_calloc(num_md_cmpts, sizeof(*origin_key->dst_md_cmpts),
                          "ucp_failover_dst_md_cmpts");
    if (!md_cmpts) {
        return UCS_ERR_NO_MEMORY;
    }

    memcpy(md_cmpts, origin_key->dst_md_cmpts,
           num_md_cmpts * sizeof(*origin_key->dst_md_cmpts));
out:
    failover_key->dst_md_cmpts = md_cmpts;
    return UCS_OK;
}

static void
ucp_failover_gen_lane_key(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx, ucp_ep_config_key_t *failover_key)
{
    uint8_t i;

    if (fo_ctx->origin_lane == failover_key->am_lane) {
        failover_key->am_lane = fo_ctx->new_lane;
        ucs_info("ucp_ep %p changed am lane to %u", ucp_ep, fo_ctx->new_lane);
        fo_ctx->lane_type |= LANE_TYPE_AM;
    }

    /* here we only replace */
    for (i = 0; i < UCP_MAX_LANES; i++) {
        if (failover_key->am_bw_lanes[i] != UCP_NULL_LANE &&
            fo_ctx->origin_lane == failover_key->am_bw_lanes[i]) {
            failover_key->am_bw_lanes[i] = fo_ctx->new_lane;
            ucs_info("ucp_ep %p changed am bw lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
            fo_ctx->lane_type |= LANE_TYPE_AM_BW;
        }

        if (failover_key->rma_lanes[i] != UCP_NULL_LANE &&
            fo_ctx->origin_lane == failover_key->rma_lanes[i]) {
            failover_key->rma_lanes[i] = fo_ctx->new_lane;
            ucs_info("ucp_ep %p changed rma lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
        }

        if (failover_key->amo_lanes[i] != UCP_NULL_LANE &&
            fo_ctx->origin_lane == failover_key->amo_lanes[i]) {
            failover_key->amo_lanes[i] = fo_ctx->new_lane;
            ucs_info("ucp_ep %p changed amo lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
        }

        if (failover_key->rma_bw_lanes[i] != UCP_NULL_LANE &&
            fo_ctx->origin_lane == failover_key->rma_bw_lanes[i]) {
            failover_key->rma_bw_lanes[i] = fo_ctx->new_lane;
            ucs_info("ucp_ep %p changed rma bw lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
            fo_ctx->lane_type |= LANE_TYPE_RMA_BW;
        }
    }

    if (fo_ctx->origin_lane == failover_key->tag_lane) {
        failover_key->tag_lane = fo_ctx->new_lane;
        ucs_info("ucp_ep %p changed key tag lane to %u", ucp_ep, fo_ctx->new_lane);
        fo_ctx->lane_type |= LANE_TYPE_TAG;
    }
    return;
}

static void
ucp_failover_change_config(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucp_ep_rndv_zcopy_config_t *zcopy_conf;
    uint8_t i;

    if (fo_ctx->origin_lane == ucp_ep->am_lane) {
        ucp_ep->am_lane = fo_ctx->new_lane;     // update ucp_ep cache
    }

    if (fo_ctx->lane_type & LANE_TYPE_RMA_BW) {
        for (i = 0; i < UCP_MAX_LANES; i++) {
            zcopy_conf = &ucp_ep_config(ucp_ep)->rndv.get_zcopy;
            if (zcopy_conf->lanes[i] != UCP_NULL_LANE &&
                fo_ctx->origin_lane == zcopy_conf->lanes[i]) {
                zcopy_conf->lanes[i] = fo_ctx->new_lane;
                ucs_info("ucp_ep %p changed get zcopy lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
            }
            zcopy_conf = &ucp_ep_config(ucp_ep)->rndv.put_zcopy;
            if (zcopy_conf->lanes[i] != UCP_NULL_LANE &&
                fo_ctx->origin_lane == zcopy_conf->lanes[i]) {
                zcopy_conf->lanes[i] = fo_ctx->new_lane;
                ucs_info("ucp_ep %p changed put zcopy lane %d to %u", ucp_ep, i, fo_ctx->new_lane);
            }
        }
    }

    if (fo_ctx->origin_lane == ucp_ep_config(ucp_ep)->tag.lane) {
        ucp_ep_config(ucp_ep)->tag.lane = fo_ctx->new_lane;
        ucs_info("ucp_ep %p changed tag lane to %u", ucp_ep, fo_ctx->new_lane);
    }
    return;
}

/*
 * multiple ucp_ep depend on the same ep_config.
 * therefore, here we create ep_config and then update ucp_ep->cfg_index.
 */
static ucs_status_t
ucp_failover_change_ucp_lane(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucp_worker_h worker = ucp_ep->worker;
    ucp_ep_config_key_t failover_key;
    ucs_status_t status;
    ucp_worker_cfg_index_t new_cfg_index;

    UCS_ASYNC_BLOCK(&worker->async);

    memcpy(&failover_key, &ucp_ep_config(ucp_ep)->key, sizeof(ucp_ep_config_key_t));

    status = ucp_failover_copy_ep_config_md_cmpts(&failover_key, &ucp_ep_config(ucp_ep)->key);
    if (status != UCS_OK) {
        UCS_ASYNC_UNBLOCK(&worker->async);
        ucs_warn("failover copy md config error, ep: %p, ret: %d", ucp_ep, status);
        return status;
    }

    ucp_failover_gen_lane_key(ucp_ep, fo_ctx, &failover_key);

    // wireup_msg_lane need to be changed before resolved ep id
    // replace config
    status = ucp_worker_get_ep_config(worker, &failover_key, 0, &new_cfg_index);
    if (status != UCS_OK) {
        if (failover_key.dst_md_cmpts) {
            ucs_free(failover_key.dst_md_cmpts);
        }
        UCS_ASYNC_UNBLOCK(&worker->async);
        ucs_error("failover get config error, ep: %p, ret: %d", ucp_ep, status);
        return status;
    }

    ucp_ep->cfg_index = new_cfg_index;

    ucp_failover_change_config(ucp_ep, fo_ctx);
    ucs_info("ep %p wireup lane %u config id %u", ucp_ep, ucp_ep_config(ucp_ep)->key.wireup_msg_lane, ucp_ep->cfg_index);

    UCS_ASYNC_UNBLOCK(&worker->async);
    return UCS_OK;
}

static ucs_status_t
ucp_failover_resend_data(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->origin_lane);
    uct_ep_h new_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->new_lane);
    ucs_status_t ret = UCS_OK;

    if (origin_ep->iface->ops.ep_resend) {
        ret = origin_ep->iface->ops.ep_resend(origin_ep, fo_ctx->peer_private_data, new_ep,
                                              &fo_ctx->rkey_ctx);
    }
    return ret;
}

static void
ucp_failover_pending_transfer(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->origin_lane);
    uct_ep_h new_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->new_lane);

    if (origin_ep->iface->ops.ep_pending_transfer) {
        /* no need to return */
        (void)origin_ep->iface->ops.ep_pending_transfer(origin_ep, new_ep);
    }
    return;
}

static void
ucp_failover_set_lane_ep_fault(ucp_ep_h ucp_ep, uint8_t index, uct_ep_fault_status_t status)
{
    failover_ctx_t *fo_ctx = ucp_ep->failover_ctx.failover_array[index];
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, fo_ctx->origin_lane);
    if (origin_ep->iface->ops.ep_set_fault) {
        origin_ep->iface->ops.ep_set_fault(origin_ep, status);
    }
    UCS_BITMAP_SET(ucp_ep->discarded_lane_bitmap, fo_ctx->origin_lane);        // discard
    ucs_info("ep %p set lane %u ep status %u", ucp_ep, fo_ctx->origin_lane, status);

    return;
}

static void
ucp_ep_failover_done(ucp_ep_h ucp_ep, uint8_t index)
{
    uct_ep_h origin_ep = ucp_ep_failover_get_lane(ucp_ep, index);
    failover_ctx_t *fo_ctx = ucp_ep->failover_ctx.failover_array[index];
    if (fo_ctx->lane_fault_type & LANE_FAULT_TYPE_IFACE && origin_ep->iface->ops.iface_set_fault_flag) {
        origin_ep->iface->ops.iface_set_fault_flag(origin_ep->iface, DEV_FO_FLAG_MIGRATED);    // stop iface progress
    }
    ucp_failover_set_lane_ep_fault(ucp_ep, index, EP_FO_FLAG_FAULT);
    ucp_ep_free_fo_ctx(ucp_ep, index);
    return;
}

static inline void
check_failover_progress_timeout(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    if (ucs_time_to_sec(ucs_get_time() - fo_ctx->cycle_time) >= UCP_FAILOVER_DEAULT_TIMEOUT) {
        ucs_warn("ep %p failover timeout %u state 0x%x", ucp_ep, UCP_FAILOVER_DEAULT_TIMEOUT, fo_ctx->state);
        fo_ctx->cycle_time = ucs_get_time();
    }
    return;
}

static void
ucp_change_tl_map(ucp_ep_h ucp_ep, uint8_t index)
{
    ucp_worker_h worker = ucp_ep->worker;
    ucp_rsc_index_t rsc_index;
    uint8_t i;
    ucp_md_index_t md_index;

    UCS_ASYNC_BLOCK(&worker->async);
    rsc_index = ucp_ep_config(ucp_ep)->key.lanes[index].rsc_index;
    md_index = worker->context->tl_rscs[rsc_index].md_index;
    UCS_BITMAP_SET(ucp_ep->discarded_rsc_bitmap, rsc_index);        // discard
    /*
     * when lane is faulty, all rscs of the same md are unavailable
     * so, here we push them in blacklist
     */
    for (i = 0; i < worker->context->num_tls; i++) {
        if (worker->context->tl_rscs[i].md_index == md_index) {
            UCS_BITMAP_SET(ucp_ep->worker->discard_tl_bitmap, i);
            ucs_info("ep %p add tls " UCT_TL_RESOURCE_DESC_FMT "[%u] to blacklist", ucp_ep,
                     UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[i].tl_rsc), i);
        }
    }

    UCS_ASYNC_UNBLOCK(&worker->async);
    return;
}

static inline
ucs_status_t ucp_failover_progress_select(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    if (!(fo_ctx->state & UCP_FO_FLAG_SELECTED)) {
        ucs_info("failover ctx is selecting, ucp_ep: %p, lane: %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane);
        ret = ucp_failover_reselect(ucp_ep, fo_ctx);
        if (ret != UCS_OK) {    // no available lane
            ucs_fatal("Failed to reselect lane! no available lane");
        } else {
            fo_ctx->state |= UCP_FO_FLAG_SELECTED;
        }
        ucs_info("failover ctx select successfully, ucp_ep: %p, lane: %u--%u, select: %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        return UCS_INPROGRESS; // may be re-selected upon return for re-entry
    }
    return UCS_OK;
}

static inline
ucs_status_t ucp_failover_progress_resolved_epid(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    if (!(fo_ctx->state & UCP_FO_FLAG_RESOLVED_EP_ID)) {
        ret = ucp_failover_change_wireup_lane(ucp_ep, fo_ctx);    // change wireup msg lane here
        if (ret != UCS_OK) {
            ucs_error("ep %p Failed to change wireup lane!", ucp_ep);
            return ret;
        }
        ret = ucp_ep_resolve_remote_id(ucp_ep, fo_ctx->new_lane);
        if (ret != UCS_OK) {
            ucs_error("ep %p Failed to resolve remote ep id!", ucp_ep);
            return ret;
        }
        fo_ctx->state |= UCP_FO_FLAG_RESOLVED_EP_ID;
    }
    return UCS_OK;
}

static inline
ucs_status_t ucp_failover_progress_pre_handle(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    if (!(fo_ctx->state & UCP_FO_FLAG_PRE_HANDLED)) {
        /* if only some eps are fault, here mey not do pre-handle */
        if (fo_ctx->lane_fault_type & LANE_FAULT_TYPE_IFACE) {
            ret = ucp_failover_pre_handle(ucp_ep, fo_ctx);
            if (ret != UCS_OK) {
                return ret;
            }
        }
        ucs_info("failover pre handle success ucp_ep: %p, lane: %u--%u => %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        fo_ctx->state |= UCP_FO_FLAG_PRE_HANDLED;
    }
    return UCS_OK;
}

static inline ucs_status_t
ucp_failover_progress_send_meta(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    int is_reply = fo_ctx->state & UCP_FO_FLAG_REPLY_META ? 1 : 0;
    if (!(fo_ctx->state & UCP_FO_FLAG_SENT)) {
        ucs_info("failover ctx is sending meta, ucp_ep: %p, lane: %u--%u => %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        ret = ucp_failover_send_meta(ucp_ep, fo_ctx, is_reply);
        if (ret != UCS_OK) {    // no available lane
            /*
             * We may not handle UCS_ERR_BUSY here,
             * because if meta sent fails here, it should trigger a new lane reselection and reset fo_ctx
             * see ucp_failover_reselect
             */
            ucs_warn("ucp_ep %p failed to send meta msg: %d! retry", ucp_ep, ret);
            // waiting lane restart or maybe reselect
            return ret;
        } else {
            if (is_reply) {
                fo_ctx->state |= UCP_FO_FLAG_REPLY;
            }
            fo_ctx->state |= UCP_FO_FLAG_SENT;
        }
        ucs_info("failover ctx send meta successfully, ucp_ep: %p, lane: %u--%u => %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        return UCS_INPROGRESS;
    }
    return UCS_OK;
}

static inline
ucs_status_t ucp_failover_progress_revise_lane(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    uint8_t j;
    failover_ctx_t *tmp_fo_ctx;
    if (!(fo_ctx->state & UCP_FO_FLAG_REVISED)) {
        // if dest lane in old fo_ctx is current fault lane,
        // old fo_ctx needs to be modified. e.g
        // if we have 0->1 before, but now we have 1->2,
        // so we need change old ctx to 0->2 and resend meta
        for (j = 0; j < ucp_ep_config(ucp_ep)->key.num_lanes; j++) {
            if (j == fo_ctx->origin_lane || j == fo_ctx->new_lane) {
                continue;
            }
            tmp_fo_ctx = ucp_ep->failover_ctx.failover_array[j];
            if (tmp_fo_ctx && tmp_fo_ctx->new_lane == fo_ctx->origin_lane) {
                tmp_fo_ctx->new_lane = fo_ctx->new_lane;
                tmp_fo_ctx->remote_new_lane = fo_ctx->remote_new_lane;
                /* inform peer to force to modify lane */
                tmp_fo_ctx->lane_type |= LANE_TYPE_REVISE;
                /* reset ctx state, need to resend meta */
                tmp_fo_ctx->state = (UCP_FO_FLAG_INIT | UCP_FO_FLAG_SELECTED);
                tmp_fo_ctx->rkey_ctx.rkey_state = UCT_RKEY_RELEASED;
                ucs_info("ep %p revise lane %u--%u => %u--%u", ucp_ep,
                         tmp_fo_ctx->origin_lane, tmp_fo_ctx->remote_origin_lane,
                         tmp_fo_ctx->new_lane, tmp_fo_ctx->remote_new_lane);
            }
        }
        fo_ctx->state |= UCP_FO_FLAG_REVISED;
        return UCS_INPROGRESS;
    }
    return UCS_OK;
}

static inline
ucs_status_t ucp_failover_progress_get_rkey(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    if (fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_INIT) {
        ret = ucp_failover_get_rkey(ucp_ep, fo_ctx);
        if (ret != UCS_OK) {
            /* if get rkey failed, maybe reget*/
            return ret;
        }
        if (!(fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_REPLIED)) {
            return UCS_INPROGRESS; // wait for rkey
        }
    }
    return UCS_OK;
}

static inline
ucs_status_t ucp_failover_progress_resend(ucp_ep_h ucp_ep, failover_ctx_t *fo_ctx)
{
    ucs_status_t ret;
    /*
     * rkey is not released for the first time, because it was not used.
     * so the sencond time, here will release rkey from the last time.
     */
    if (fo_ctx->rkey_ctx.rkey_state & UCT_RKEY_USED) {
        ret = ucp_failover_release_rkey(ucp_ep, fo_ctx);
        if (ret != UCS_OK) {
            return ret;
        }
        /* pass through */
    }
    if (!(fo_ctx->state & UCP_FO_FLAG_RESEND)) {
        ucs_info("failover ctx is resending data, ucp_ep: %p, lane: %u--%u => %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        ret = ucp_failover_resend_data(ucp_ep, fo_ctx);
        if (ret != UCS_OK) {
            if (ret != UCS_INPROGRESS) {
                ucs_info("failover resend data failed, ucp_ep: %p, ret: %d", ucp_ep, ret);
            }
            return ret;
        }
        ucs_info("failover ctx resend data successfully, ucp_ep: %p, lane: %u--%u => %u--%u",
                 ucp_ep, fo_ctx->origin_lane, fo_ctx->remote_origin_lane,
                 fo_ctx->new_lane, fo_ctx->remote_new_lane);
        fo_ctx->state |= UCP_FO_FLAG_RESEND;

        return UCS_INPROGRESS;     // loop back again to release rkey
    }
    return UCS_OK;
}

static void
ucp_failover_progress_lane(ucp_ep_h ucp_ep, uint8_t index)
{
    failover_ctx_t *fo_ctx = ucp_ep->failover_ctx.failover_array[index];
    check_failover_progress_timeout(ucp_ep, fo_ctx);
    if (!(ucp_ep->flags & UCP_EP_FLAG_REMOTE_CONNECTED)) {
        /* need to wait for aux connected when aux ep fault */
        return;
    }
    if (!(fo_ctx->state & UCP_FO_FLAG_CHANGE_TL_MAP)) { /* set discard map */
        if (fo_ctx->lane_fault_type & LANE_FAULT_TYPE_IFACE) {
            ucp_change_tl_map(ucp_ep, index);
        }
        /* LANE_FAULT_TYPE_EP */
        ucp_failover_set_lane_ep_fault(ucp_ep, index, EP_FO_FLAG_IN_PROGRESS);
        fo_ctx->state |= UCP_FO_FLAG_CHANGE_TL_MAP;
        return;
    }
    if (ucp_failover_progress_select(ucp_ep, fo_ctx) != UCS_OK) {   /* reselect */
        return;
    }
    if (ucp_failover_progress_resolved_epid(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }
    if (!(ucp_ep->flags & UCP_EP_FLAG_REMOTE_ID)) {
        // wait for resolved remote id
        return;
    }
    if (ucp_failover_progress_pre_handle(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }
    if (ucp_failover_progress_send_meta(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }
    if (!(fo_ctx->state & UCP_FO_FLAG_REPLY)) {
        // wait for reply
        return;
    }
    if (ucp_failover_progress_revise_lane(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }
    if (ucp_failover_progress_get_rkey(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }
    if (ucp_failover_progress_resend(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }

    if(ucp_failover_change_ucp_lane(ucp_ep, fo_ctx) != UCS_OK) {
        return;
    }

    // after changed lane, we need to handle user pending req
    // because some reqs are in pending arbiter for some reasons
    ucp_failover_pending_transfer(ucp_ep, fo_ctx);

    ucs_info("failover finished, ucp_ep: %p", ucp_ep);
    ucp_ep_failover_done(ucp_ep, index);
    return;
}

static unsigned
ucp_failover_progress(void *args)
{
    ucp_ep_h ucp_ep = (ucp_ep_h)args;
    uint8_t handle_count = 0;
    uint8_t i;
    UCS_ASYNC_BLOCK(&ucp_ep->worker->async);
    for (i = 0; i < UCP_MAX_LANES; i++) {
        if (ucp_ep->failover_ctx.failover_array[i]) {
            ucp_failover_progress_lane(ucp_ep, i);
            handle_count++;
        }
    }

    if (handle_count == 0) {    // already no tasks
        uct_worker_progress_unregister_safe(ucp_ep->worker->uct, &ucp_ep->failover_ctx.failover_id);
    }
    UCS_ASYNC_UNBLOCK(&ucp_ep->worker->async);

    return 0;
}

static ucp_lane_index_t
ucp_ep_get_matched_lane(ucp_ep_h ucp_ep, uct_iface_h uct_iface, lane_type_t *lane_type)
{
    ucp_ep_config_key_t *key = &ucp_ep_config(ucp_ep)->key;
    int i;
    ucp_lane_index_t lane;
    ucp_lane_index_t ret_lane = UCP_NULL_LANE;
    // am_bw_lanes
    for (i = 0; i < UCP_MAX_LANES; i++) {
        lane = key->am_bw_lanes[i];
        if (lane != UCP_NULL_LANE && uct_iface == ucp_ep_get_iface_from_lane(ucp_ep, lane)) {
            *lane_type |= LANE_TYPE_AM_BW;
            ret_lane = lane;
            break;
        }
    }
    // rma bw lane
    for (i = 0; i < UCP_MAX_LANES; i++) {
        lane = key->rma_bw_lanes[i];
        if (lane != UCP_NULL_LANE && uct_iface == ucp_ep_get_iface_from_lane(ucp_ep, lane)) {
            *lane_type |= LANE_TYPE_RMA_BW;
            ret_lane = lane;
            break;
        }
    }
    // am lane
    lane = key->am_lane;
    if (lane != UCP_NULL_LANE && uct_iface == ucp_ep_get_iface_from_lane(ucp_ep, lane)) {
        *lane_type |= LANE_TYPE_AM;
        ret_lane = lane;
    }
    // key tag lane
    lane = key->tag_lane;
    if (lane != UCP_NULL_LANE && uct_iface == ucp_ep_get_iface_from_lane(ucp_ep, lane)) {
        *lane_type |= LANE_TYPE_KEY_TAG;
        ret_lane = lane;
    }
    // tag lane
    if (ret_lane != UCP_NULL_LANE && ret_lane == ucp_ep_config(ucp_ep)->tag.lane) {
        *lane_type |= LANE_TYPE_TAG;
    }
    // wireup msg lane
    if (ret_lane != UCP_NULL_LANE && ret_lane == key->wireup_msg_lane) {
        *lane_type |= LANE_TYPE_WIREUP_MSG;
    }

    return ret_lane;
}

// lock protected
ucs_status_t
ucp_worker_iface_failover_error_handler(void *arg, uct_iface_h uct_iface)
{
    ucp_worker_h worker = (ucp_worker_h)arg;
    ucp_rsc_index_t rsc_index;
    ucs_status_t ret;
    ucp_lane_index_t lane;
    lane_type_t lane_type;
    int need_retry = 0;
    ucp_ep_ext_t *ep_ext;
    ucp_ep_h ucp_ep;
    ucs_info("ucp layer senses failover iface %p, starting worker %p", uct_iface, worker);
    ucs_list_for_each(ep_ext, &worker->all_eps, ep_list) {
        ucp_ep = ep_ext->ep;
        lane_type = 0;
        lane = ucp_ep_get_matched_lane(ucp_ep, uct_iface, &lane_type);
        if (lane == UCP_NULL_LANE) {
            continue;
        }

        rsc_index = ucp_ep_config(ucp_ep)->key.lanes[lane].rsc_index;
        if (!ucp_ep->failover_ctx.failover_array[lane]) {
            ret = ucp_ep_create_fo_ctx(ucp_ep, lane, lane_type, LANE_FAULT_TYPE_IFACE);        // init
            if (ret != UCS_OK) {
                need_retry = 1;
                continue;
            }
            ucs_info("ep failover init sucessfully, rsc_index=%u, " UCT_TL_RESOURCE_DESC_FMT
                     " lane=%u, worker=%p, lane_type=%u, ucp_ep=%p", rsc_index,
                     UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[rsc_index].tl_rsc),
                     lane, worker, lane_type, ucp_ep);
            uct_worker_progress_register_safe(worker->uct, ucp_failover_progress, ucp_ep,
                                              UCS_CALLBACKQ_FLAG_FAST, &ucp_ep->failover_ctx.failover_id);
        }
    }

    if (need_retry) {
        return UCS_ERR_NO_RESOURCE;
    }

    return UCS_OK;
}

void
ucp_failover_lane_connect_fault_handler(ucp_ep_h ucp_ep, ucp_lane_index_t lane)
{
    ucp_worker_h worker = ucp_ep->worker;
    ucp_rsc_index_t rsc_index;
    ucs_status_t ret;

    if (ucp_ep->failover_ctx.failover_array[lane]) {
        /* already exists */
        return;
    }

    ucs_info("ucp layer failover lane ucp_ep %p lane %u, starting worker %p", ucp_ep, lane, worker);
    ret = ucp_ep_create_fo_ctx(ucp_ep, lane, 0, LANE_FAULT_TYPE_EP);        // init
    if (ret != UCS_OK) {
        // no handle
        ucs_fatal("no memory for createing fo ctx");
    }
    rsc_index = ucp_ep_config(ucp_ep)->key.lanes[lane].rsc_index;
    ucs_info("failover init sucessfully, rsc_index=%u, " UCT_TL_RESOURCE_DESC_FMT
                " lane=%u, worker=%p, lane_type=%u, ucp_ep=%p", rsc_index,
                UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[rsc_index].tl_rsc),
                lane, worker, 0, ucp_ep);
    uct_worker_progress_register_safe(worker->uct, ucp_failover_progress, ucp_ep,
                                        UCS_CALLBACKQ_FLAG_FAST, &ucp_ep->failover_ctx.failover_id);
}

// lock protected
ucs_status_t
ucp_worker_ep_failover_error_handler(void *arg, uct_ep_h uct_ep)
{
    ucp_worker_h worker = (ucp_worker_h)arg;
    ucp_ep_ext_t *ep_ext;
    int lane = 0;
    ucp_ep_h ucp_ep = NULL;
    uct_ep_h tmp_uct_ep;
    int find = 0;
    ucs_status_t ret;
    ucp_rsc_index_t rsc_index;

    ucs_info("ucp layer senses failover ep %p iface %p, starting worker %p", uct_ep, uct_ep->iface, worker);
    /* find matched ucp_ep and lane */
    ucs_list_for_each(ep_ext, &worker->all_eps, ep_list) {
        ucp_ep = ep_ext->ep;
        for (lane = 0; lane < ucp_ep_config(ucp_ep)->key.num_lanes; lane++) {
            tmp_uct_ep = ucp_ep_failover_get_lane(ucp_ep, lane);
            if (tmp_uct_ep == uct_ep) {
                find = 1;
                break;
            }
        }
        if (find) {
            break;
        }
    }

    if (find) {
        if (ucp_ep->failover_ctx.failover_array[lane]) {
            /* already in failover progress */
            return UCS_OK;
        }

        ret = ucp_ep_create_fo_ctx(ucp_ep, lane, 0, LANE_FAULT_TYPE_EP);        // init
        if (ret != UCS_OK) {
            return UCS_ERR_NO_RESOURCE;
        }
        rsc_index = ucp_ep_config(ucp_ep)->key.lanes[lane].rsc_index;
        ucs_info("ep failover init sucessfully, rsc_index=%u, " UCT_TL_RESOURCE_DESC_FMT
                 " lane=%u, worker=%p, lane_type=%u, ucp_ep=%p", rsc_index,
                 UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[rsc_index].tl_rsc),
                 lane, worker, 0, ucp_ep);
        uct_worker_progress_register_safe(worker->uct, ucp_failover_progress, ucp_ep,
                                          UCS_CALLBACKQ_FLAG_FAST, &ucp_ep->failover_ctx.failover_id);
    }

    return UCS_OK;
}

static void
ucp_ep_failover_handle_conflicts(ucp_ep_h ucp_ep, ucp_failover_info_t *info, failover_ctx_t *ctx)
{
    if (ucs_unlikely(info->lane_type & LANE_TYPE_REVISE)) { /* multi-point fault */
        ctx->new_lane = info->remote_new_lane;
        ctx->remote_new_lane = info->new_lane;
        ctx->state = UCP_FO_FLAG_INIT | UCP_FO_FLAG_SELECTED;
        ucs_info("failover ctx force to revise, use incoming, ucp_ep=%p, lane: %u--%u => %u--%u",
                    ucp_ep, ctx->origin_lane, ctx->remote_origin_lane,
                    ctx->new_lane, ctx->remote_new_lane);
        ctx->state |= UCP_FO_FLAG_REPLY_META;
        /* here we still need to update private_data */
        ctx->peer_private_data = info->private_data;
        return;
    }
    if (!(ctx->state & UCP_FO_FLAG_SELECTED)) {
        ctx->new_lane = info->remote_new_lane;
        ctx->remote_new_lane = info->new_lane;
        ctx->state |= UCP_FO_FLAG_SELECTED;
        ucs_info("failover ctx just init, use incoming, ucp_ep=%p, lane: %u--%u => %u--%u",
                    ucp_ep, ctx->origin_lane, ctx->remote_origin_lane,
                    ctx->new_lane, ctx->remote_new_lane);
        ctx->state |= UCP_FO_FLAG_REPLY_META;
    } else if (!(ctx->state & UCP_FO_FLAG_SENT)) {  // need decision
        if (ctx->new_lane != info->remote_new_lane &&
            ucp_get_device_guid(ucp_ep_failover_get_lane(ucp_ep, ctx->origin_lane)) < info->guid) {   // choose bigger one
            ctx->new_lane = info->remote_new_lane;
            ctx->remote_new_lane = info->new_lane;
        }
        ucs_info("failover ctx already selected, after decision, ucp_ep=%p, lane: %u--%u => %u--%u",
                    ucp_ep, ctx->origin_lane, ctx->remote_origin_lane,
                    ctx->new_lane, ctx->remote_new_lane);
        ctx->state |= UCP_FO_FLAG_REPLY_META;
    } else if (!(ctx->state & UCP_FO_FLAG_REPLY)) { // need decision
        if (ctx->new_lane != info->remote_new_lane &&
            ucp_get_device_guid(ucp_ep_failover_get_lane(ucp_ep, ctx->origin_lane)) < info->guid) {   // choose bigger one
            ctx->new_lane = info->remote_new_lane;
            ctx->remote_new_lane = info->new_lane;
        }
        ucs_info("failover ctx already sent meta, after decision, ucp_ep=%p, lane: %u--%u => %u--%u",
                    ucp_ep, ctx->origin_lane, ctx->remote_origin_lane,
                    ctx->new_lane, ctx->remote_new_lane);
        ctx->state |= UCP_FO_FLAG_REPLY;
    }
    ctx->peer_private_data = info->private_data;
    return;
}

static void
ucp_ep_failover_handle_fault_recv(ucp_ep_h ucp_ep, ucp_failover_info_t *info, ucp_lane_index_t lane)
{
    failover_ctx_t *ctx = NULL;
    ucs_status_t ret;

    ret = ucp_ep_create_fo_ctx(ucp_ep, info->remote_origin_lane, info->lane_type, LANE_FAULT_TYPE_EP);   // init
    if (ret != UCS_OK) {
        ucs_error("Failed to create failover ctx: %d!", ret);
        return;
    }
    /*
     * peer end of the lane is faulty, not the local end,
     * so, the local end does not need to be in blacklist.
     */
    ctx = ucp_ep->failover_ctx.failover_array[info->remote_origin_lane];
    if (info->origin_lane != ctx->remote_origin_lane) {
        ucs_fatal("ep %p recv lane %u => remote_lane %u but actual %u",
                  ucp_ep, info->remote_origin_lane, info->origin_lane, ctx->remote_origin_lane);
    }
    ctx->new_lane = info->remote_new_lane;
    ctx->remote_new_lane = info->new_lane;
    ctx->state |= UCP_FO_FLAG_SELECTED;
    ctx->state |= UCP_FO_FLAG_REPLY_META;
    ctx->peer_private_data = info->private_data;
    uct_worker_progress_register_safe(ucp_ep->worker->uct, ucp_failover_progress, ucp_ep,
                                      UCS_CALLBACKQ_FLAG_FAST, &ucp_ep->failover_ctx.failover_id);
}

static int
ucp_ep_check_lane_already_fault(ucp_ep_h ucp_ep, ucp_lane_index_t lane)
{
    ucp_rsc_index_t rsc_index;
    if (UCS_BITMAP_GET(ucp_ep->discarded_lane_bitmap, lane)) {  // already fault
        return 1;
    }

    rsc_index = ucp_ep_config(ucp_ep)->key.lanes[lane].rsc_index;
    if (UCS_BITMAP_GET(ucp_ep->discarded_rsc_bitmap, rsc_index)) {  // already fault
        return 1;
    }
    return 0;
}

static void
ucp_ep_failover_handle(ucp_ep_h ucp_ep, ucp_failover_info_t *info)
{
    failover_ctx_t *ctx = NULL;

    ucs_info("failover receive meta, ucp_ep %p, type %u, lane: %u--%u => %u--%u",
             ucp_ep, info->lane_type, info->remote_origin_lane, info->origin_lane,
             info->remote_new_lane, info->new_lane);

    if (ucp_ep_check_lane_already_fault(ucp_ep, info->remote_new_lane)) {
        ucs_info("ucp_ep %p failover lane already fault, discard", ucp_ep);
        return;
    }

    if (ucp_ep->failover_ctx.failover_array[info->remote_origin_lane]) {    // already in progress
        ctx = ucp_ep->failover_ctx.failover_array[info->remote_origin_lane];
        ucs_info("failover ctx already init, ucp_ep=%p, lane: %u--%u",
                 ucp_ep, ctx->remote_origin_lane, ctx->origin_lane);
        ucp_ep_failover_handle_conflicts(ucp_ep, info, ctx);
    } else {
        ucs_info("failover ctx not init, ucp_ep=%p, lane: %u--%u => %u--%u",
                 ucp_ep, info->remote_origin_lane, info->origin_lane,
                 info->remote_new_lane, info->new_lane);
        ucp_ep_failover_handle_fault_recv(ucp_ep, info, info->remote_origin_lane);
    }
    return;
}

static void
ucp_ep_failover_handle_reply(ucp_ep_h ucp_ep, ucp_failover_info_t *info)
{
    failover_ctx_t *ctx = NULL;
    ucs_info("fialover recv meta reply, ucp_ep: %p lane: %u--%u => %u--%u",
             ucp_ep, info->remote_origin_lane, info->origin_lane,
             info->remote_new_lane, info->new_lane);
    if (ucp_ep_check_lane_already_fault(ucp_ep, info->remote_new_lane)) {
        ucs_info("ucp_ep %p failover reply lane already fault, discard", ucp_ep);
        return;
    }
    if (ucp_ep->failover_ctx.failover_array[info->remote_origin_lane]) {
        ctx = ucp_ep->failover_ctx.failover_array[info->remote_origin_lane];
        if (ctx->new_lane != info->remote_new_lane && ctx->guid < info->guid) {   // need decision
            ctx->new_lane = info->remote_new_lane;
            ctx->remote_new_lane = info->new_lane;
        }
        ctx->peer_private_data = info->private_data;
        ctx->state |= UCP_FO_FLAG_REPLY;
    }
    return;
}

static void
ucp_ep_failover_handle_reply_revise(ucp_ep_h ucp_ep, ucp_failover_info_t *info)
{
    failover_ctx_t *ctx = NULL;
    ucs_info("fialover recv meta reply revise, lane: %u--%u => %u--%u",
             info->origin_lane, info->remote_origin_lane,
             info->new_lane, info->remote_new_lane);
    if (ucp_ep->failover_ctx.failover_array[info->remote_origin_lane]) {
        ctx = ucp_ep->failover_ctx.failover_array[info->remote_origin_lane];
        ctx->lane_type &= ~LANE_TYPE_REVISE;
        ctx->state |= UCP_FO_FLAG_REPLY;
    }
    return;
}

static uct_rkey_t
ucp_ep_failover_get_rkey(ucp_ep_h ucp_ep, ucp_lane_index_t lane,
                         uint64_t addr, size_t length, uct_mem_h *memh_p)
{
    ucs_status_t status;
    uct_md_h md;
    ucp_md_index_t md_index;
    ucp_rsc_index_t rsc_index;
    uct_mem_h memh;
    unsigned flag = UCT_MD_MEM_ACCESS_ALL;  // provides all including atomic
    ucp_ep_config_key_t *key = &ucp_ep_config(ucp_ep)->key;
    uct_rkey_t rkey = UCT_INVALID_RKEY;
    uct_md_attr_t md_attr;

    // get md
    ucp_context_h context = ucp_ep->worker->context;
    rsc_index  = key->lanes[lane].rsc_index;
    md_index = context->tl_rscs[rsc_index].md_index;
    md = context->tl_mds[md_index].md;

    status = uct_md_query(md, &md_attr);
    if (status != UCS_OK) {
        ucs_error("failover remote get rkey failed: query md failed %d", status);
        return rkey;
    }

    // currently, only IB rkey can be got. and only uint64_t is valid.
    if (md_attr.rkey_packed_size != sizeof(uct_rkey_t)) {
        ucs_error("failover remote get rkey failed: rkey attr not matched %lu != %lu",
                  md_attr.rkey_packed_size, sizeof(uct_rkey_t));
        return rkey;
    }

    status = uct_md_mem_reg(md, (void *)addr, length, flag, &memh);
    if (status != UCS_OK) {
        ucs_error("failover remote get rkey failed: reg mem failed %d", status);
        return rkey;
    }

    // it's safe to load mem in uint64_t
    status = uct_md_mkey_pack(md, memh, &rkey);
    if (status != UCS_OK) {
        ucs_error("failover remote get rkey failed: pack rkey failed %d", status);
        (void)uct_md_mem_dereg(md, memh);
        return rkey;
    }

    ucs_info("get rkey successful addr %p length %lu rkey %lu memh %p",
             (void *)addr, length, rkey, memh);

    *memh_p = memh;
    return rkey;
}

static void
ucp_ep_failover_release_rkey(ucp_ep_h ucp_ep, ucp_lane_index_t lane, uct_mem_h memh)
{
    ucp_rsc_index_t rsc_index;
    ucp_md_index_t md_index;
    uct_md_h md;
    ucp_ep_config_key_t *key = &ucp_ep_config(ucp_ep)->key;

    // get md
    ucp_context_h context = ucp_ep->worker->context;
    rsc_index  = key->lanes[lane].rsc_index;
    md_index = context->tl_rscs[rsc_index].md_index;
    md = context->tl_mds[md_index].md;

    if (memh) {
        (void)uct_md_mem_dereg(md, memh);
        ucs_info("release rkey successful memh %p", memh);
    }
    return;
}

static void
ucp_ep_failover_get_rkey_handler(ucp_ep_h ucp_ep, ucp_rkey_handle_t *req)
{
    ucs_status_t ret;
    uct_ep_h comm_ep;
    uint64_t remote_id;

    comm_ep = ucp_ep_failover_get_lane(ucp_ep, req->remote_new_lane);
    remote_id = (uint64_t)ucp_ep_remote_id(ucp_ep);

    req->rkey = ucp_ep_failover_get_rkey(ucp_ep, req->remote_new_lane, req->addr, req->length, ((uct_mem_h *)&(req->memh)));
    req->msg_type = MSG_TYPE_RESP_RKEY;
    ret = uct_ep_am_short(comm_ep, UCP_AM_ID_RKEY_HANDLER, remote_id, req, sizeof(*req));
    if (ret != UCS_OK) {
        // add pending ?
        ucs_error("reply rkey msg error %u", ret);
    }
    return;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_failover_handler, (arg, data, length, flags),
                 void *arg, void *data, size_t length, unsigned flags)
{
    ucp_worker_h worker = (ucp_worker_h)arg;
    ucp_ep_h ucp_ep;

    uint64_t *ep_id = (uint64_t *)data;
    ucp_failover_info_t *info = (ucp_failover_info_t *)(ep_id + 1);

    UCP_WORKER_GET_VALID_EP_BY_ID(&ucp_ep, worker, *ep_id, return UCS_OK, "ucp failover handler");

    switch (info->msg_type) {
    case META_MSG_TYPE_REQ:
        ucp_ep_failover_handle(ucp_ep, info);
        break;
    case META_MSG_TYPE_RESP:
        ucp_ep_failover_handle_reply(ucp_ep, info);
        break;
    case META_MSG_TYPE_RESP_REVICE:
        ucp_ep_failover_handle_reply_revise(ucp_ep, info);
        break;
    default:
        ucs_error("invalid meta msg type %d", info->msg_type);
        break;
    }

    return UCS_OK;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_failover_rkey_handler, (arg, data, length, flags),
                 void *arg, void *data, size_t length, unsigned flags)
{
    ucp_worker_h worker = (ucp_worker_h)arg;
    ucp_ep_h ucp_ep;
    ucp_rkey_handle_t *req;
    failover_ctx_t *ctx = NULL;

    uint64_t *ep_id = (uint64_t *)data;
    UCP_WORKER_GET_VALID_EP_BY_ID(&ucp_ep, worker, *ep_id, return UCS_OK, "ucp failover rkey handler");

    req = (ucp_rkey_handle_t *)(ep_id + 1);
    if (req->msg_type == MSG_TYPE_GET_RKEY) {
        ucp_ep_failover_get_rkey_handler(ucp_ep, req);
    } else if (req->msg_type == MSG_TYPE_RESP_RKEY) {
        if (ucp_ep->failover_ctx.failover_array[req->origin_lane]) {
            ctx = ucp_ep->failover_ctx.failover_array[req->origin_lane];
            ctx->rkey_ctx.rkey = (uct_rkey_t)req->rkey;
            ctx->rkey_ctx.memh = req->memh;
            ctx->rkey_ctx.rkey_state |= UCT_RKEY_REPLIED;
            ucs_info("ep %p rkey reply", ucp_ep);
        }
    } else { /* MSG_TYPE_RELEASE_RKEY */
        ucp_ep_failover_release_rkey(ucp_ep, req->remote_new_lane, (uct_mem_h)(uintptr_t)req->memh);
    }
    return UCS_OK;
}

UCP_DEFINE_AM(UCP_FEATURE_TAG | UCP_FEATURE_AM | UCP_FEATURE_RMA | UCP_FEATURE_AMO32, UCP_AM_ID_FAILOVER_HANDLER,
              ucp_failover_handler, NULL, 0);
UCP_DEFINE_AM(UCP_FEATURE_TAG | UCP_FEATURE_AM | UCP_FEATURE_RMA | UCP_FEATURE_AMO32, UCP_AM_ID_RKEY_HANDLER,
              ucp_failover_rkey_handler, NULL, 0);
