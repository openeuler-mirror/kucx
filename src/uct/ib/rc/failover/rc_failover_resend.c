/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#include <uct/ib/base/ib_log.h>
#include <uct/ib/base/ib_failover.h>
#include <uct/ib/rc/base/rc_failover.h>
#include <uct/ib/rc/verbs/rc_verbs.h>
#include <uct/ib/rc/verbs/rc_verbs_impl.h>

#include "rc_failover.h"

static uint16_t
uct_rc_txqp_fo_completion_desc(uct_rc_verbs_ep_t *origin_ep, uint16_t ts_ack)
{
    uct_rc_iface_send_op_t *op;
    int valid_flag = 0;
    uint16_t ts_last_sn;
    uint16_t need_resend_ts_cnt;   // Number of two-side op to be resent
    uint16_t ts_qlen;
    uint16_t ts_release_num;
    uct_rc_txqp_t *txqp = &origin_ep->super.txqp;
    uint16_t i = 0;
    uint16_t ret_cnt = 0;
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_ep, uct_rc_failover_ep_t);

    /* 
     * first we calculate resending num we need 
     * pi - pc is two-side total num we sent
     * two-side_total_num - ts_ack is two-side resending num
     * ts_qlen - two-side_resend_num is two-side release num
     */
    need_resend_ts_cnt = (uint16_t)((uint16_t)(origin_ep->txcnt.pi - fo_ep->oscnt.tx_pc) - ts_ack);
    ts_qlen = (uint16_t)ucs_queue_length(&txqp->outstanding);
    ucs_assert_always(UCS_CIRCULAR_COMPARE16(ts_qlen, >=, need_resend_ts_cnt));
    ts_release_num = (uint16_t)(ts_qlen - need_resend_ts_cnt);

    ucs_info("completion handle ep %p pi %u ci %u pc %u cc %u ack %u resend_cnt %u ts_qlen %u ts_release_num %u",
             origin_ep, origin_ep->txcnt.pi, origin_ep->txcnt.ci, fo_ep->oscnt.tx_pc, fo_ep->oscnt.tx_cc,
             ts_ack, need_resend_ts_cnt, ts_qlen, ts_release_num);

    /* For two-side resources, we release op according to count. */
    ucs_queue_for_each_extract(op, &txqp->outstanding, queue,
                               UCS_CIRCULAR_COMPARE16(i, <, ts_release_num)) {
        i++;
        ts_last_sn = op->sn;
        valid_flag = 1;
        uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
    }
    ret_cnt = ts_release_num;
    /* For one-side resources, we release them according to two-side last sn, 
     * because one-side resources in outq are allowed to be repeatedly sent, because they are not acked */
    if (valid_flag) {
        ucs_queue_for_each_extract(op, &fo_ep->outstanding_os, queue,
                                   UCS_CIRCULAR_COMPARE16(op->sn, <=, ts_last_sn)) {
            uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
            ret_cnt++;
        }
    }

    return ret_cnt;
}

static ucs_status_t
uct_rc_failover_ep_resend_prepare(uct_rc_verbs_ep_t *origin_ep, uint64_t priv_data)
{
    uct_rc_iface_t *iface = ucs_derived_of(origin_ep->super.super.super.iface, uct_rc_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_ep, uct_rc_failover_ep_t);
    uint16_t peer_ack = (uint16_t)priv_data;        // it's safe to convert u64 to u16 here
    uint16_t count;
    if (fo_ep->fo_resend_prepare_flag) {      // only do once
        return UCS_OK;
    }
    fo_ep->fo_resend_prepare_flag = 1;

    // clear tx outstanding_q
    count = uct_rc_txqp_fo_completion_desc(origin_ep, peer_ack);

    origin_ep->txcnt.ci += count;
    uct_rc_txqp_available_add(&origin_ep->super.txqp, count);
    uct_rc_iface_update_reads(iface);
    uct_rc_iface_add_cq_credits(iface, count);
    return UCS_OK;
}

// am bcopy callback
static size_t
uct_rc_resend_am_bcopy_pack(void *dest, void *arg)
{
    uct_rc_iface_send_desc_t *desc = (uct_rc_iface_send_desc_t *)arg;
    uct_rc_hdr_t *hdr = (uct_rc_hdr_t *)(desc + 1);
    size_t len = desc->super.buf_info->bcopy.length;
    memcpy(dest, (void *)(hdr + 1), len);
    return len;
}

static ucs_status_t
uct_rc_failover_ep_do_resend_am_bcopy(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    ssize_t bcopy_len;
    uct_rc_hdr_t *hdr = (uct_rc_hdr_t *)(desc + 1);

    hdr->am_id &= ~UCT_RC_EP_FC_MASK;
    bcopy_len = uct_ep_am_bcopy(&new_rc_ep->super.super.super, hdr->am_id, uct_rc_resend_am_bcopy_pack, desc, 0);
    if (bcopy_len != desc->super.buf_info->bcopy.length) {
        ucs_error("failed to send bcopy %d", (ucs_status_t)bcopy_len);
        return (ucs_status_t)bcopy_len;
    }

    return UCS_OK;
}

static ucs_status_t
uct_rc_failover_zcopy_reg_mem(uct_md_h md, uct_rc_buf_info_t *buf_info, zcopy_resend_comp_t *zcopy_comp)
{
    uct_md_attr_t md_attr;
    ucs_status_t ret = UCS_OK;
    uint16_t i, j;
    (void)uct_md_query(md, &md_attr);
    for (i = 0; i < buf_info->zcopy.iovcnt; i++) {
        if (md_attr.cap.flags & UCT_MD_FLAG_NEED_MEMH) {
            ret = uct_md_mem_reg(md, buf_info->zcopy.iov[i].buffer,
                                 buf_info->zcopy.iov[i].length * buf_info->zcopy.iov[i].count,
                                 UCT_MD_MEM_ACCESS_RMA, &buf_info->zcopy.iov[i].memh);
            if (ret != UCS_OK) {
                ucs_error("failed to reg zcopy mem %d", ret);
                for (j = 0; j < i; j++) {
                    uct_md_mem_dereg(zcopy_comp->md, zcopy_comp->memh[i]);
                }
                return ret;
            }
        } else {
            buf_info->zcopy.iov[i].memh = NULL;
        }
        zcopy_comp->memh[i] = buf_info->zcopy.iov[i].memh;
    }
    zcopy_comp->memh_num = buf_info->zcopy.iovcnt;
    return UCS_OK;
}

static ucs_status_t
uct_rc_failover_ep_do_resend_am_zcopy(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep)
{
    ucs_status_t ret;
    zcopy_resend_comp_t *zcopy_comp;
    uint16_t i;
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    uct_rc_hdr_t *hdr = (uct_rc_hdr_t *)(desc + 1);
    uct_rc_iface_t *iface = ucs_derived_of(new_rc_ep->super.super.super.iface, uct_rc_iface_t);
    uct_rc_buf_info_t *buf_info = op->buf_info;
    uct_md_h md = iface->super.super.md;

    hdr->am_id &= ~UCT_RC_EP_FC_MASK;

    zcopy_comp = ucs_calloc(1, sizeof(*zcopy_comp), "zcopy resend comp");
    if (!zcopy_comp) {
        ucs_error("failed to alloc zcopy comp");
        return UCS_ERR_NO_MEMORY;
    }
    zcopy_comp->md = md;
    if (uct_rc_failover_zcopy_reg_mem(md, buf_info, zcopy_comp) != UCS_OK) {
        ucs_error("failed to reg zopy mem");
        ucs_free(zcopy_comp);
        return UCS_ERR_NO_MEMORY;
    }
    if (desc->super.user_comp) {
        zcopy_comp->origin_uct_comp = desc->super.user_comp;
    }
    zcopy_comp->uct_comp.func = uct_ib_resend_zcopy_completion_cb;
    zcopy_comp->uct_comp.count = 1;

    ret = uct_ep_am_zcopy(&new_rc_ep->super.super.super, hdr->am_id, hdr + 1, buf_info->zcopy.header_length,
                          buf_info->zcopy.iov, buf_info->zcopy.iovcnt, 0 /* unused */,
                          &zcopy_comp->uct_comp);
    if (ret != UCS_INPROGRESS) {    // UCS_INPROGRESS means UCS_OK in zcopy
        ucs_error("failed to send zcopy %d", ret);
        for (i = 0; i < zcopy_comp->memh_num; i++) {
            if (zcopy_comp->memh[i]) {
                uct_md_mem_dereg(zcopy_comp->md, zcopy_comp->memh[i]);
            }
        }
        ucs_free(zcopy_comp);
        return ret;
    }
    if (desc->super.user_comp) {
        desc->super.user_comp->count++;      // ref need increase
    }
    return UCS_OK;
}

static void uct_init_rkey_ctx(uct_rkey_ctx_t *rkey_ctx, uint64_t addr, uint64_t length)
{
    rkey_ctx->rkey_state = UCT_RKEY_INIT;
    rkey_ctx->addr = addr;
    rkey_ctx->length = length;
    rkey_ctx->rkey = UCT_INVALID_RKEY;
    rkey_ctx->memh = 0;
    ucs_info("rkey ctx init %p %lu", (void *)addr, length);
}

/*
 * rdma one-side resending depends on some things:
 * 1. recv-end must reg mem on mds of multi ifaces at the same time, see ucp_rndv_reg_send_buffer -> ucp_mem_rereg_mds
 * 2. send-end must provide the user_comp that can re-obtain rkey.
 */
static ucs_status_t
uct_rc_failover_ep_do_resend_rdma_zcopy(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep,
                                        uct_rkey_ctx_t *rkey_ctx)
{
    ucs_status_t ret;
    zcopy_resend_comp_t *zcopy_comp;
    uct_rc_iface_t *iface = ucs_derived_of(new_rc_ep->super.super.super.iface, uct_rc_iface_t);
    uct_rc_buf_info_t *buf_info = op->buf_info;
    uct_md_h md = iface->super.super.md;
    uct_rkey_t rkey = UCT_INVALID_RKEY;
    uint16_t i;

    // need to get rkey
    if (!(rkey_ctx->rkey_state & UCT_RKEY_REPLIED)) {
        ucs_info("rdma zcopy need get rkey");
        uct_init_rkey_ctx(rkey_ctx, buf_info->zcopy.remote_addr, op->length);
        return UCS_ERR_NO_ELEM;
    }

    zcopy_comp = ucs_calloc(1, sizeof(*zcopy_comp), "zcopy resend comp");
    if (!zcopy_comp) {
        ucs_error("failed to alloc zcopy comp");
        return UCS_ERR_NO_MEMORY;
    }

    // 1. re-reg memh
    zcopy_comp->md = md;
    if (uct_rc_failover_zcopy_reg_mem(md, buf_info, zcopy_comp) != UCS_OK) {
        ucs_error("failed to reg zopy mem");
        ucs_free(zcopy_comp);
        return UCS_ERR_NO_MEMORY;
    }
    rkey = rkey_ctx->rkey;
    if (op->user_comp) {
        zcopy_comp->origin_uct_comp = op->user_comp;
    }
    zcopy_comp->uct_comp.func = uct_ib_resend_zcopy_completion_cb;
    zcopy_comp->uct_comp.count = 1;

    /*
     * rdma get/put must use rkey.
     */
    ucs_assert_always(rkey != UCT_INVALID_RKEY);
    if (buf_info->op_type == UCT_EP_OP_GET_ZCOPY) {
        ret = uct_ep_get_zcopy(&new_rc_ep->super.super.super, buf_info->zcopy.iov, buf_info->zcopy.iovcnt,
                               buf_info->zcopy.remote_addr, rkey, &zcopy_comp->uct_comp);
    } else {
        ret = uct_ep_put_zcopy(&new_rc_ep->super.super.super, buf_info->zcopy.iov, buf_info->zcopy.iovcnt,
                               buf_info->zcopy.remote_addr, rkey, &zcopy_comp->uct_comp);
    }
    if (ret != UCS_INPROGRESS) {
        ucs_error("failed to get zcopy %d", ret);
        for (i = 0; i < zcopy_comp->memh_num; i++) {
            if (zcopy_comp->memh[i]) {
                uct_md_mem_dereg(zcopy_comp->md, zcopy_comp->memh[i]);
            }
        }
        ucs_free(zcopy_comp);
        return ret;
    }

    if (op->user_comp) {
        op->user_comp->count++;      // ref need increase
    }

    rkey_ctx->rkey_state |= UCT_RKEY_USED;

    return UCS_OK;
}

static ucs_status_t
uct_rc_failover_ep_do_resend_get_bcopy(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep,
                                       uct_rkey_ctx_t *rkey_ctx)
{
    ucs_status_t ret;
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    uct_rkey_t rkey = UCT_INVALID_RKEY;

    // need to get rkey
    if (!(rkey_ctx->rkey_state & UCT_RKEY_REPLIED)) {
        ucs_info("rdma get bcopy need get rkey");
        uct_init_rkey_ctx(rkey_ctx, op->buf_info->rdma.remote_addr, op->length);
        return UCS_ERR_NO_ELEM;
    }
    rkey = rkey_ctx->rkey;
    ucs_assert_always(rkey != UCT_INVALID_RKEY);
    ret = uct_ep_get_bcopy(&new_rc_ep->super.super.super, desc->unpack_cb, op->unpack_arg, op->length,
                           op->buf_info->rdma.remote_addr, rkey, op->user_comp);
    if (ret != UCS_INPROGRESS) {
        ucs_error("failed to get bcopy %d", ret);
        return ret;
    }
    if (op->user_comp) {
        op->user_comp->count++;      // ref need increase
    }

    rkey_ctx->rkey_state |= UCT_RKEY_USED;

    return UCS_OK;
}


static ucs_status_t
uct_rc_failover_ep_do_resend_atomic64_fetch(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep,
                                            uct_rkey_ctx_t *rkey_ctx)
{
    ucs_status_t ret;
    uct_rkey_t rkey = UCT_INVALID_RKEY;

    // need to get rkey
    if (!(rkey_ctx->rkey_state & UCT_RKEY_REPLIED)) {
        ucs_info("rdma get bcopy need get rkey");
        uct_init_rkey_ctx(rkey_ctx, op->buf_info->atomic.remote_addr, sizeof(uint64_t));
        return UCS_ERR_NO_ELEM;
    }
    rkey = rkey_ctx->rkey;
    ucs_assert_always(rkey != UCT_INVALID_RKEY);
    if (op->buf_info->atomic.opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) {
        ret = uct_ep_atomic64_fetch(&new_rc_ep->super.super.super, UCT_ATOMIC_OP_ADD, op->buf_info->atomic.swap,
                                    op->buffer, op->buf_info->atomic.remote_addr, rkey, op->user_comp);
    } else { /* IBV_WR_ATOMIC_CMP_AND_SWP */
        ret = uct_ep_atomic_cswap64(&new_rc_ep->super.super.super, op->buf_info->atomic.compare_add,
                                    op->buf_info->atomic.swap, op->buf_info->atomic.remote_addr, rkey, op->buffer,
                                    op->user_comp);
    }

    if (ret != UCS_INPROGRESS) {
        ucs_error("failed to atomic fetch %d", ret);
        return ret;
    }

    if (op->user_comp) {
        op->user_comp->count++;      // ref need increase
    }

    rkey_ctx->rkey_state |= UCT_RKEY_USED;

    return UCS_OK;
}

// bcopy callback
static size_t
uct_rc_resend_bcopy_pack(void *dest, void *arg)
{
    uct_rc_iface_send_desc_t *desc = (uct_rc_iface_send_desc_t *)arg;
    size_t len = desc->super.buf_info->rdma.length;
    memcpy(dest, (void *)(desc + 1), len);
    return len;
}

static ucs_status_t
uct_rc_failover_ep_do_resend_put_bcopy(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep,
                                       uct_rkey_ctx_t *rkey_ctx)
{
    uct_rkey_t rkey = UCT_INVALID_RKEY;
    ssize_t ret;
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);

    // need to get rkey
    if (!(rkey_ctx->rkey_state & UCT_RKEY_REPLIED)) {
        ucs_info("rdma get bcopy need get rkey");
        uct_init_rkey_ctx(rkey_ctx, op->buf_info->rdma.remote_addr, op->buf_info->rdma.length);
        return UCS_ERR_NO_ELEM;
    }
    rkey = rkey_ctx->rkey;

    ret = uct_ep_put_bcopy(&new_rc_ep->super.super.super, uct_rc_resend_bcopy_pack, desc,
                           op->buf_info->rdma.remote_addr, rkey);
    if (ret != op->buf_info->rdma.length) {
        ucs_error("failed to put bcopy %d", (ucs_status_t)ret);
        return (ucs_status_t)ret;
    }

    rkey_ctx->rkey_state |= UCT_RKEY_USED;

    return UCS_OK;
}

static ucs_status_t
uct_rc_failover_ep_do_resend_atomic64_post(uct_rc_iface_send_op_t *op, uct_rc_verbs_ep_t *new_rc_ep,
                                           uct_rkey_ctx_t *rkey_ctx)
{
    uct_rkey_t rkey = UCT_INVALID_RKEY;
    ucs_status_t ret;

    // need to get rkey
    if (!(rkey_ctx->rkey_state & UCT_RKEY_REPLIED)) {
        ucs_info("rdma get bcopy need get rkey");
        uct_init_rkey_ctx(rkey_ctx, op->buf_info->atomic.remote_addr, sizeof(uint64_t));
        return UCS_ERR_NO_ELEM;
    }
    rkey = rkey_ctx->rkey;

    ret = uct_ep_atomic64_post(&new_rc_ep->super.super.super, op->buf_info->atomic.opcode,
                               op->buf_info->atomic.compare_add, op->buf_info->atomic.remote_addr, rkey);
    if (ret != UCS_OK) {
        ucs_error("failed to atomic post %d", ret);
        return ret;
    }

    rkey_ctx->rkey_state |= UCT_RKEY_USED;

    return UCS_OK;
}

/* get op with the minimum sn from the one-side queue and two-side queue, noop return NULL*/
static uct_rc_iface_send_op_t *
uct_rc_failover_ep_get_first_op(uct_rc_verbs_ep_t *origin_rc_ep, ucs_queue_iter_t *iter_p, int *is_oneside)
{
    uct_rc_iface_send_op_t *op = NULL;
    uct_rc_iface_send_op_t *op_os = NULL;
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_rc_ep, uct_rc_failover_ep_t);
    uct_rc_txqp_t *txqp = &origin_rc_ep->super.txqp;
    ucs_queue_iter_t iter = ucs_queue_iter_begin(&txqp->outstanding);
    ucs_queue_iter_t iter_os = ucs_queue_iter_begin(&fo_ep->outstanding_os);
    if (!ucs_queue_iter_end(&txqp->outstanding, iter)) {
        op = (uct_rc_iface_send_op_t *)(*iter);
    }
    if (!ucs_queue_iter_end(&fo_ep->outstanding_os, iter_os)) {
        op_os = (uct_rc_iface_send_op_t *)(*iter_os);
    }
    if (op && op_os) {
        if (UCS_CIRCULAR_COMPARE16(op->sn, <, op_os->sn)) {
            *is_oneside = 0;
            *iter_p = iter;
            return op;
        }
        *is_oneside = 1;
        *iter_p = iter_os;
        return op_os;
    }
    if (op) {
        *is_oneside = 0;
        *iter_p = iter;
        return op;
    }
    if (op_os) {
        *is_oneside = 1;
        *iter_p = iter_os;
        return op_os;
    }
    return NULL;
}

static void
uct_rc_failover_ep_delete_iter(uct_rc_verbs_ep_t *origin_rc_ep, ucs_queue_iter_t iter, int is_oneside)
{
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_rc_ep, uct_rc_failover_ep_t);
    uct_rc_txqp_t *txqp = &origin_rc_ep->super.txqp;
    if (is_oneside) {
        ucs_queue_del_iter(&fo_ep->outstanding_os, iter);
        return;
    }
    ucs_queue_del_iter(&txqp->outstanding, iter);
}

static ucs_status_t
uct_rc_failover_ep_do_resend(uct_rc_verbs_ep_t *origin_rc_ep, uct_rc_verbs_ep_t *new_rc_ep,
                             uct_rkey_ctx_t *rkey_ctx)
{
    ucs_queue_iter_t iter;
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_rc_ep, uct_rc_failover_ep_t);
    uct_rc_iface_send_op_t *op;
    ucs_status_t ret = UCS_OK;
    int is_oneside = -1;

    ucs_info("failover ep %p pi %u, ci %u ospc %u oscc %u", origin_rc_ep, origin_rc_ep->txcnt.pi,
             origin_rc_ep->txcnt.ci, fo_ep->oscnt.tx_pc, fo_ep->oscnt.tx_cc);

    // the rest of op in outstanding_q should be resent
    op = uct_rc_failover_ep_get_first_op(origin_rc_ep, &iter, &is_oneside);
    if (op != NULL) {
        ucs_info("failover resend op type %u sn %u", op->buf_info->op_type, op->sn);
        switch (op->buf_info->op_type) {
        case UCT_EP_OP_AM_SHORT:
        case UCT_EP_OP_AM_BCOPY:
            ret = uct_rc_failover_ep_do_resend_am_bcopy(op, new_rc_ep);
            break;
        case UCT_EP_OP_AM_ZCOPY:
            ret = uct_rc_failover_ep_do_resend_am_zcopy(op, new_rc_ep);
            break;
        case UCT_EP_OP_GET_ZCOPY:
        case UCT_EP_OP_PUT_ZCOPY:
            ret = uct_rc_failover_ep_do_resend_rdma_zcopy(op, new_rc_ep, rkey_ctx);
            break;
        case UCT_EP_OP_GET_BCOPY:
            ret = uct_rc_failover_ep_do_resend_get_bcopy(op, new_rc_ep, rkey_ctx);
            break;
        case UCT_EP_OP_ATOMIC_FETCH:
            ret = uct_rc_failover_ep_do_resend_atomic64_fetch(op, new_rc_ep, rkey_ctx);
            break;
        case UCT_EP_OP_PUT_BCOPY:
        case UCT_EP_OP_PUT_SHORT:
            ret = uct_rc_failover_ep_do_resend_put_bcopy(op, new_rc_ep, rkey_ctx);
            break;
        case UCT_EP_OP_ATOMIC_POST:
            ret = uct_rc_failover_ep_do_resend_atomic64_post(op, new_rc_ep, rkey_ctx);
            break;
        case UCT_EP_OP_LAST:
            ret = UCS_OK;
            break;
        default:
            ucs_fatal("unrealized op %u", op->buf_info->op_type);
        }

        if (ret != UCS_OK) {
            return ret;
        }

        uct_rc_failover_ep_delete_iter(origin_rc_ep, iter, is_oneside);
        uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
        return UCS_INPROGRESS;
    }
    return UCS_OK;
}

static void
uct_rc_verbs_ep_resend_post(uct_rc_verbs_ep_t *origin_ep)
{
    uct_rc_iface_t *iface = ucs_derived_of(origin_ep->super.super.super.iface, uct_rc_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(origin_ep, uct_rc_failover_ep_t);
    uint16_t count = origin_ep->txcnt.pi - origin_ep->txcnt.ci;
    ucs_info("failover rc: pi %u, ci %u, txpc %u txcc %u", origin_ep->txcnt.pi, origin_ep->txcnt.ci,
             fo_ep->oscnt.tx_pc, fo_ep->oscnt.tx_cc);
    origin_ep->txcnt.ci = origin_ep->txcnt.pi;
    fo_ep->oscnt.tx_cc = fo_ep->oscnt.tx_pc;
    uct_rc_txqp_available_add(&origin_ep->super.txqp, count);
    uct_rc_iface_update_reads(iface);
    uct_rc_iface_add_cq_credits(iface, count);

    uct_rc_fc_restore_wnd(iface, &origin_ep->super.fc);
}

ucs_status_t
uct_rc_failover_ep_failover_resend_progress(uct_ep_h origin_ep, uint64_t priv_data, uct_ep_h new_ep,
                                            uct_rkey_ctx_t *rkey_ctx)
{
    ucs_status_t ret;
    uct_rc_verbs_ep_t *origin_rc_ep = ucs_derived_of(origin_ep, uct_rc_verbs_ep_t);
    uct_rc_verbs_ep_t *new_rc_ep = ucs_derived_of(new_ep, uct_rc_verbs_ep_t);

    // 1. for origin ep, clear already sent [txcnt.ci + 1, ack]
    ret = uct_rc_failover_ep_resend_prepare(origin_rc_ep, priv_data);
    if (ret != UCS_OK) {
        return ret;
    }

    // 2. for origin ep, resend [ack + 1, txcnt.pi] in outstanding_q
    ret = uct_rc_failover_ep_do_resend(origin_rc_ep, new_rc_ep, rkey_ctx);
    if (ret != UCS_OK) {
        return ret;
    }

    // 3, release origin ep
    uct_rc_verbs_ep_resend_post(origin_rc_ep);

    return UCS_OK;
}