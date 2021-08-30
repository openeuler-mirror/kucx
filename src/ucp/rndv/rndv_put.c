/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "proto_rndv.inl"
#include "rndv_mtype.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/proto/proto_am.inl>
#include <ucp/proto/proto_multi.inl>
#include <ucp/proto/proto_single.inl>


enum {
    /* Initial stage for put zcopy is sending the data */
    UCP_PROTO_RNDV_PUT_ZCOPY_STAGE_SEND = UCP_PROTO_STAGE_START,

    /* Initial stage for put memtype is copy the data to the fragment */
    UCP_PROTO_RNDV_PUT_MTYPE_STAGE_COPY = UCP_PROTO_STAGE_START,

    /* Flush all lanes to ensure remote delivery */
    UCP_PROTO_RNDV_PUT_STAGE_FLUSH,

    /* Send ATP without fence (could be done after a flush) */
    UCP_PROTO_RNDV_PUT_STAGE_ATP,

    /* Send ATP with fence (could be done if using send lanes for ATP) */
    UCP_PROTO_RNDV_PUT_STAGE_FENCED_ATP,

    /* Memtype only: send the fragment to the remote side */
    UCP_PROTO_RNDV_PUT_MTYPE_STAGE_SEND
};

typedef struct ucp_proto_rndv_put_priv {
    uct_completion_callback_t  put_comp_cb;
    uct_completion_callback_t  atp_comp_cb;
    uint8_t                    stage_after_put;
    ucp_lane_map_t             flush_map;
    ucp_lane_map_t             atp_map;
    ucp_lane_index_t           atp_num_lanes;
    ucp_proto_rndv_bulk_priv_t bulk;
} ucp_proto_rndv_put_priv_t;


static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_send(ucp_request_t *req,
                               const ucp_proto_multi_lane_priv_t *lpriv,
                               const uct_iov_t *iov, uct_completion_t *comp)
{
    ucp_rkey_h rkey         = req->send.rndv.rkey;
    uct_rkey_t tl_rkey      = rkey->tl_rkey[lpriv->super.rkey_index].rkey.rkey;
    uint64_t remote_address = req->send.rndv.remote_address +
                              req->send.state.dt_iter.offset;

    return uct_ep_put_zcopy(req->send.ep->uct_eps[lpriv->super.lane], iov, 1,
                            remote_address, tl_rkey, comp);
}

static void
ucp_proto_rndv_put_common_flush_completion_send_atp(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;

    ucp_trace_req(req, "rndv_put_common_completion_send_atp");
    ucp_proto_completion_init(&req->send.state.uct_comp, rpriv->atp_comp_cb);
    ucp_proto_request_set_stage(req, UCP_PROTO_RNDV_PUT_STAGE_ATP);
    ucp_request_send(req);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_flush_send(ucp_request_t *req, ucp_lane_index_t lane)
{
    ucp_ep_h ep = req->send.ep;

    ucp_trace_req(req, "flush lane[%d] " UCT_TL_RESOURCE_DESC_FMT, lane,
                  UCT_TL_RESOURCE_DESC_ARG(ucp_ep_get_tl_rsc(ep, lane)));
    return uct_ep_flush(ep->uct_eps[lane], 0, &req->send.state.uct_comp);
}

static ucs_status_t
ucp_proto_rndv_put_common_flush_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);

    return ucp_proto_multi_lane_map_progress(
            req, &req->send.rndv.put.flush_map,
            ucp_proto_rndv_put_common_flush_send);
}

static size_t ucp_proto_rndv_put_common_pack_atp(void *dest, void *arg)
{
    ucp_request_t *req                     = arg;
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_rndv_send_pack_atp(req, dest, rpriv->atp_num_lanes);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_atp_send(ucp_request_t *req, ucp_lane_index_t lane)
{
    const ucp_proto_rndv_put_priv_t UCS_V_UNUSED *rpriv =
            req->send.proto_config->priv;

    ucp_trace_req(req, "send ATP lane %d count %d", lane, rpriv->atp_num_lanes);
    return ucp_proto_am_bcopy_single_send(req, UCP_AM_ID_RNDV_ATP, lane,
                                          ucp_proto_rndv_put_common_pack_atp,
                                          req, sizeof(ucp_rndv_atp_hdr_t));
}

static ucs_status_t
ucp_proto_rndv_put_common_atp_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);

    return ucp_proto_multi_lane_map_progress(req, &req->send.rndv.put.atp_map,
                                             ucp_proto_rndv_put_common_atp_send);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_fenced_atp_send(ucp_request_t *req,
                                          ucp_lane_index_t lane)
{
    ucs_status_t status;

    status = uct_ep_fence(req->send.ep->uct_eps[lane], 0);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    return ucp_proto_rndv_put_common_atp_send(req, lane);
}

static ucs_status_t
ucp_proto_rndv_put_common_fenced_atp_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);

    return ucp_proto_multi_lane_map_progress(
            req, &req->send.rndv.put.atp_map,
            ucp_proto_rndv_put_common_fenced_atp_send);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_data_sent(ucp_request_t *req)
{
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;

    ucp_trace_req(req, "rndv_put_common_data_sent");
    ucp_proto_request_set_stage(req, rpriv->stage_after_put);
    return UCS_INPROGRESS;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_put_common_complete(ucp_request_t *req)
{
    ucp_trace_req(req, "rndv_put_common_complete");
    ucp_proto_rndv_rkey_destroy(req);
    ucp_proto_request_zcopy_complete(req, req->send.state.uct_comp.status);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_put_common_request_init(ucp_request_t *req)
{
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;

    req->send.rndv.put.atp_map   = rpriv->atp_map;
    req->send.rndv.put.flush_map = rpriv->flush_map;
    ucp_proto_rndv_bulk_request_init(req, &rpriv->bulk);
}

static ucs_status_t
ucp_proto_rndv_put_common_init(const ucp_proto_init_params_t *init_params,
                               uint64_t rndv_modes, size_t max_length,
                               uct_ep_operation_t memtype_op, unsigned flags,
                               ucp_md_map_t initial_reg_md_map,
                               uct_completion_callback_t comp_cb,
                               int support_ppln)
{
    const size_t atp_size                = sizeof(ucp_rndv_atp_hdr_t);
    ucp_context_t *context               = init_params->worker->context;
    ucp_proto_rndv_put_priv_t *rpriv     = init_params->priv;
    ucp_proto_multi_init_params_t params = {
        .super.super         = *init_params,
        .super.overhead      = 0,
        .super.latency       = 0,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority  = 0,
        .super.min_length    = 0,
        .super.max_length    = max_length,
        .super.min_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.min_zcopy),
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.max_zcopy),
        .super.max_iov_offs  = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.hdr_size      = 0,
        .super.memtype_op    = memtype_op,
        .super.flags         = flags | UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS,
        .max_lanes           = context->config.ext.max_rndv_lanes,
        .initial_reg_md_map  = initial_reg_md_map,
        .first.tl_cap_flags  = UCT_IFACE_FLAG_PUT_ZCOPY,
        .first.lane_type     = UCP_LANE_TYPE_RMA_BW,
        .middle.tl_cap_flags = UCT_IFACE_FLAG_PUT_ZCOPY,
        .middle.lane_type    = UCP_LANE_TYPE_RMA_BW,
    };
    const uct_iface_attr_t *iface_attr;
    ucp_lane_index_t lane_idx, lane;
    int send_atp, use_fence;
    size_t bulk_priv_size;
    ucs_status_t status;

    if ((init_params->select_param->dt_class != UCP_DATATYPE_CONTIG) ||
        !ucp_proto_rndv_op_check(init_params, UCP_OP_ID_RNDV_SEND,
                                 support_ppln)) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_bulk_init(&params, &rpriv->bulk, &bulk_priv_size);
    if (status != UCS_OK) {
        return status;
    }

    *init_params->priv_size = ucs_offsetof(ucp_proto_rndv_put_priv_t, bulk) +
                              bulk_priv_size;

    /* Check if all potential lanes support sending ATP */
    rpriv     = params.super.super.priv;
    send_atp  = !ucp_proto_rndv_init_params_is_ppln_frag(init_params);
    use_fence = send_atp && !context->config.ext.rndv_put_force_flush;

    /* Check if all potential lanes support sending ATP */
    lane_idx  = 0;
    while (use_fence && (lane_idx < rpriv->bulk.mpriv.num_lanes)) {
        lane       = rpriv->bulk.mpriv.lanes[lane_idx++].super.lane;
        iface_attr = ucp_proto_common_get_iface_attr(init_params, lane);
        use_fence  = use_fence &&
                     (((iface_attr->cap.flags & UCT_IFACE_FLAG_AM_SHORT) &&
                       (iface_attr->cap.am.max_short >= atp_size)) ||
                      ((iface_attr->cap.flags & UCT_IFACE_FLAG_AM_BCOPY) &&
                       (iface_attr->cap.am.max_bcopy >= atp_size)));
    }

    /* All lanes can send ATP - invalidate am_lane, to use mpriv->lanes.
     * Otherwise, would need to flush all lanes and send ATP on
     * rpriv->super.lane when the flush is completed
     */
    if (use_fence) {
        /* Send fence followed by ATP on all lanes */
        rpriv->bulk.super.lane = UCP_NULL_LANE;
        rpriv->put_comp_cb     = comp_cb;
        rpriv->atp_comp_cb     = NULL;
        rpriv->stage_after_put = UCP_PROTO_RNDV_PUT_STAGE_FENCED_ATP;
        rpriv->flush_map       = 0;
        rpriv->atp_map         = rpriv->bulk.mpriv.lane_map;
    } else {
        /* Flush all lanes and send single ATP on control message lane */
        if (send_atp) {
            rpriv->put_comp_cb =
                    ucp_proto_rndv_put_common_flush_completion_send_atp;
            rpriv->atp_comp_cb = comp_cb;
            rpriv->atp_map     = UCS_BIT(rpriv->bulk.super.lane);
        } else {
            rpriv->put_comp_cb = comp_cb;
            rpriv->atp_comp_cb = NULL;
            rpriv->atp_map     = 0;
        }
        rpriv->stage_after_put = UCP_PROTO_RNDV_PUT_STAGE_FLUSH;
        rpriv->flush_map       = rpriv->bulk.mpriv.lane_map;
        ucs_assert(rpriv->flush_map != 0);
    }

    if (send_atp) {
        ucs_assert(rpriv->atp_map != 0);
    }
    rpriv->atp_num_lanes = ucs_popcount(rpriv->atp_map);

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_zcopy_send_func(ucp_request_t *req,
                                   const ucp_proto_multi_lane_priv_t *lpriv,
                                   ucp_datatype_iter_t *next_iter)
{
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;
    size_t max_payload;
    uct_iov_t iov;

    max_payload = ucp_proto_rndv_bulk_max_payload(req, &rpriv->bulk, lpriv);
    ucp_datatype_iter_next_iov(&req->send.state.dt_iter, max_payload,
                               lpriv->super.memh_index,
                               UCS_BIT(UCP_DATATYPE_CONTIG), next_iter, &iov,
                               1);
    return ucp_proto_rndv_put_common_send(req, lpriv, &iov,
                                          &req->send.state.uct_comp);
}

static ucs_status_t
ucp_proto_rndv_put_zcopy_send_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_multi_zcopy_progress(
            req, &rpriv->bulk.mpriv, ucp_proto_rndv_put_common_request_init,
            UCT_MD_MEM_ACCESS_LOCAL_READ, UCS_BIT(UCP_DATATYPE_CONTIG),
            ucp_proto_rndv_put_zcopy_send_func,
            ucp_proto_rndv_put_common_data_sent, rpriv->put_comp_cb);
}

static void ucp_proto_rndv_put_zcopy_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    ucp_proto_rndv_put_common_complete(req);
}

static ucs_status_t
ucp_proto_rndv_put_zcopy_init(const ucp_proto_init_params_t *init_params)
{
    unsigned flags = UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY;

    return ucp_proto_rndv_put_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_ZCOPY),
                                          SIZE_MAX, UCT_EP_OP_LAST, flags, 0,
                                          ucp_proto_rndv_put_zcopy_completion,
                                          0);
}

static void ucp_proto_rndv_put_config_str(size_t min_length, size_t max_length,
                                          const void *priv,
                                          ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_put_priv_t *rpriv = priv;

    ucp_proto_rndv_bulk_config_str(min_length, max_length, &rpriv->bulk, strb);
    if (rpriv->flush_map != 0) {
        ucs_string_buffer_appendf(strb, " flush:");
        ucs_string_buffer_append_flags(strb, rpriv->flush_map, NULL);
    }
    if (rpriv->atp_map != 0) {
        ucs_string_buffer_appendf(strb, " atp:");
        ucs_string_buffer_append_flags(strb, rpriv->atp_map, NULL);
    }
}

static ucp_proto_t ucp_rndv_put_zcopy_proto = {
    .name        = "rndv/put/zcopy",
    .flags       = 0,
    .init        = ucp_proto_rndv_put_zcopy_init,
    .config_str  = ucp_proto_rndv_put_config_str,
    .progress    = {
        [UCP_PROTO_RNDV_PUT_ZCOPY_STAGE_SEND] = ucp_proto_rndv_put_zcopy_send_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_FLUSH]      = ucp_proto_rndv_put_common_flush_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_ATP]        = ucp_proto_rndv_put_common_atp_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_FENCED_ATP] = ucp_proto_rndv_put_common_fenced_atp_progress,
    },
};
UCP_PROTO_REGISTER(&ucp_rndv_put_zcopy_proto);


static void ucp_proto_rndv_put_mtype_pack_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    const ucp_proto_rndv_put_priv_t *rpriv;

    ucp_trace_req(req, "mtype_pack_completion mdesc %p", req->send.rndv.mdesc);

    rpriv = req->send.proto_config->priv;
    ucp_proto_completion_init(&req->send.state.uct_comp, rpriv->put_comp_cb);
    ucp_proto_request_set_stage(req, UCP_PROTO_RNDV_PUT_MTYPE_STAGE_SEND);
    ucp_request_send(req);
}

static UCS_F_ALWAYS_INLINE ucs_status_t ucp_proto_rndv_put_mtype_send_func(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *lpriv,
        ucp_datatype_iter_t *next_iter)
{
    const ucp_proto_rndv_put_priv_t *rpriv = req->send.proto_config->priv;
    uct_iov_t iov;

    ucp_proto_rndv_mtype_next_iov(req, &rpriv->bulk, lpriv, next_iter, &iov);
    return ucp_proto_rndv_put_common_send(req, lpriv, &iov,
                                          &req->send.state.uct_comp);
}

static ucs_status_t
ucp_proto_rndv_put_mtype_copy_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    ucs_status_t status;

    ucs_assert(!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED));

    status = ucp_proto_rndv_mtype_request_init(req);
    if (status != UCS_OK) {
        ucp_proto_request_abort(req, status);
        return UCS_OK;
    }

    ucp_proto_rndv_put_common_request_init(req);
    ucp_proto_rndv_mtype_copy(req, uct_ep_get_zcopy,
                              ucp_proto_rndv_put_mtype_pack_completion,
                              "in from");

    req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    return UCS_OK;
}

static ucs_status_t
ucp_proto_rndv_put_mtype_send_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_put_priv_t *rpriv;

    ucs_assert(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED);

    rpriv = req->send.proto_config->priv;
    return ucp_proto_multi_progress(req, &rpriv->bulk.mpriv,
                                    ucp_proto_rndv_put_mtype_send_func,
                                    ucp_proto_rndv_put_common_data_sent,
                                    UCS_BIT(UCP_DATATYPE_CONTIG));
}

static void ucp_proto_rndv_put_mtype_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_trace_req(req, "rndv_put_mtype_completion");
    ucs_mpool_put(req->send.rndv.mdesc);
    ucp_proto_rndv_put_common_complete(req);
}

static void ucp_proto_rndv_put_mtype_frag_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_trace_req(req, "rndv_put_mtype_frag_completion");
    ucs_mpool_put(req->send.rndv.mdesc);
    ucp_proto_rndv_ppln_send_frag_complete(req, 1);
}

static ucs_status_t
ucp_proto_rndv_put_mtype_init(const ucp_proto_init_params_t *init_params)
{
    uct_completion_callback_t comp_cb;
    ucp_md_map_t mdesc_md_map;
    ucs_status_t status;
    size_t frag_size;

    status = ucp_proto_rndv_mtype_init(init_params, &mdesc_md_map, &frag_size);
    if (status != UCS_OK) {
        return status;
    }

    if (ucp_proto_rndv_init_params_is_ppln_frag(init_params)) {
        comp_cb = ucp_proto_rndv_put_mtype_frag_completion;
    } else {
        comp_cb = ucp_proto_rndv_put_mtype_completion;
    }

    return ucp_proto_rndv_put_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_PIPELINE),
                                          frag_size, UCT_EP_OP_GET_ZCOPY, 0,
                                          mdesc_md_map, comp_cb, 1);
}

static ucp_proto_t ucp_rndv_put_mtype_proto = {
    .name        = "rndv/put/mtype",
    .flags       = 0,
    .init        = ucp_proto_rndv_put_mtype_init,
    .config_str  = ucp_proto_rndv_put_config_str,
    .progress    = {
        [UCP_PROTO_RNDV_PUT_MTYPE_STAGE_COPY] = ucp_proto_rndv_put_mtype_copy_progress,
        [UCP_PROTO_RNDV_PUT_MTYPE_STAGE_SEND] = ucp_proto_rndv_put_mtype_send_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_FLUSH]      = ucp_proto_rndv_put_common_flush_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_ATP]        = ucp_proto_rndv_put_common_atp_progress,
        [UCP_PROTO_RNDV_PUT_STAGE_FENCED_ATP] = ucp_proto_rndv_put_common_fenced_atp_progress,
    },
};
UCP_PROTO_REGISTER(&ucp_rndv_put_mtype_proto);
