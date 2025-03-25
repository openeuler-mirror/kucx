/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#include <uct/ib/base/ib_log.h>
#include <uct/ib/base/ib_failover.h>
#include <uct/ib/rc/base/rc_failover.h>
#include <uct/ib/rc/verbs/rc_verbs.h>
#include <uct/ib/rc/verbs/rc_verbs_impl.h>

#include <ucs/async/async.h>

#include "rc_failover.h"

static unsigned
uct_rc_failover_ep_upcall_progress(void *args)
{
    uct_rc_failover_ep_t *fo_ep = (uct_rc_failover_ep_t *)args;
    uct_ib_iface_t *ib_iface = ucs_derived_of(fo_ep->super.super.super.super.iface, uct_ib_iface_t);
    uct_worker_h worker = (uct_worker_h)ib_iface->super.worker;
    ucs_status_t status = UCS_OK;

    UCS_ASYNC_BLOCK(ib_iface->super.worker->async);
    if (ib_iface->failover.ops.ep_failure_handle) {
        status = ib_iface->failover.ops.ep_failure_handle(&fo_ep->super.super.super.super);
    }
    if (status == UCS_OK) {
        uct_worker_progress_unregister_safe(worker,
                                            &fo_ep->prog_id);
    }
    UCS_ASYNC_UNBLOCK(ib_iface->super.worker->async);

    return (status == UCS_OK);
}

/* this func is used to handle ep failover after iface failover ctx done */
static void
uct_rc_failover_ep_upcall(uct_rc_failover_ep_t *fo_ep)
{
    uct_ib_iface_t *ib_iface = ucs_derived_of(fo_ep->super.super.super.super.iface, uct_ib_iface_t);
    uct_worker_h worker = (uct_worker_h)ib_iface->super.worker;
    if (uct_ib_check_iface_fault_flag(ib_iface) != DEV_FO_FLAG_MIGRATED) {
        return;
    }
    if (fo_ep->fault_flag) {
        return;
    }

    uct_worker_progress_register_safe(worker, uct_rc_failover_ep_upcall_progress,
        fo_ep, UCS_CALLBACKQ_FLAG_FAST, &fo_ep->prog_id);

    return;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_fence_put(uct_rc_verbs_iface_t *iface, uct_rc_verbs_ep_t *ep,
                             uct_rkey_t *rkey, uint64_t *addr)
{
    uct_rc_ep_fence_put(&iface->super, &ep->fi, rkey, addr,
                        ep->super.atomic_mr_offset);
}

/* add op to one-sided outstanding queue */
static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_add_fo_send_op(uct_rc_verbs_ep_t *ep, uct_rc_iface_send_op_t *op)
{
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);
    ucs_assertv(!(op->flags & UCT_RC_IFACE_SEND_OP_FLAG_INUSE), "op=%p", op);
    op->flags |= UCT_RC_IFACE_SEND_OP_FLAG_INUSE;
    ucs_queue_push(&fo_ep->outstanding_os, &op->queue);
    return;
}

/* push queue */
static UCS_F_ALWAYS_INLINE void
uct_rc_failover_add_send_op_sn(uct_rc_verbs_ep_t *ep, uct_rc_iface_send_op_t *op, uint16_t sn, int is_oneside)
{
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);
    uct_rc_txqp_t *txqp = &fo_ep->super.super.txqp;
    ucs_trace_poll("txqp %p add send op %p sn %d handler %s", txqp, op, sn,
                   ucs_debug_get_symbol_name((void*)op->handler));
    op->sn = sn;
    if (!is_oneside) {
        uct_rc_txqp_add_send_op(txqp, op);
        return;
    }
    uct_rc_failover_ep_add_fo_send_op(ep, op);
    return;
}

/*
 * during flush and fc_ctl, extra desc needs to be allocated to fill in outstandingq,
 * so that no wrong data is sent during resending stage,
 * flush and fc_ctl do not need to be resended.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_rc_failover_ep_fill_outstanding(uct_rc_verbs_ep_t* ep)
{
    uct_rc_iface_send_desc_t *desc;
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    // maybe return UCS_ERR_NO_RESOURCE
    UCT_RC_IFACE_GET_TX_DESC(&iface->super, &iface->short_desc_mp, desc);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.handler = uct_rc_fo_send_handler;
    desc->super.user_comp = NULL;
    desc->super.buf_info->op_type = UCT_EP_OP_LAST;     /* we do not need to handle this op during failover */
    /* there is only one-side fill-scenario */
    uct_rc_failover_add_send_op_sn(ep, &desc->super, ep->txcnt.pi, 1 /* one-side */);
    return UCS_OK;
}

/*
 * 1) ibv_send
 * 2) pi++
 * 3) avail--
 */
static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_post_send(uct_rc_verbs_iface_t *iface, uct_rc_verbs_ep_t *ep,
                             struct ibv_send_wr *wr, int send_flags, int max_log_sge)
{
    struct ibv_send_wr *bad_wr;
    int ret;
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);

    ucs_assertv(ep->qp->state == IBV_QPS_RTS, "iface %p ep %p QP 0x%x state is %d",
                iface, ep, ep->qp->qp_num, ep->qp->state);

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_IN_PROGRESS)) {
        uct_rc_verbs_txqp_posted(&ep->super.txqp, &ep->txcnt, &iface->super, send_flags & IBV_SEND_SIGNALED);
        return;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        uct_rc_verbs_txqp_posted(&ep->super.txqp, &ep->txcnt, &iface->super, send_flags & IBV_SEND_SIGNALED);
        return;
    }

    if (!(send_flags & IBV_SEND_SIGNALED)) {
        send_flags |= uct_rc_iface_tx_moderation(&iface->super, &ep->super.txqp,
                                                 IBV_SEND_SIGNALED);
    }
    if (wr->opcode == IBV_WR_RDMA_READ) {
        send_flags |= uct_rc_ep_fm(&iface->super, &ep->fi, IBV_SEND_FENCE);
    }

    wr->send_flags = send_flags;
    wr->wr_id      = ep->txcnt.pi + 1;

    uct_ib_log_post_send(&iface->super.super, ep->qp, wr, max_log_sge,
                         (wr->opcode == IBV_WR_SEND) ? uct_rc_ep_packet_dump : NULL);

    ret = ibv_post_send(ep->qp, wr, &bad_wr);
    if (ucs_unlikely(ret != 0)) {
        if (ret == EFAULT) {
            ucs_error("ifce %p ibv_post_send return %d, device fault", iface, ret);
            uct_ib_set_iface_fault_flag(&iface->super.super, DEV_FO_FLAG_IN_PROGRESS);
        } else {
            ucs_fatal("ibv_post_send() returned %d (%m)", ret);
        }
    }

    uct_rc_verbs_txqp_posted(&ep->super.txqp, &ep->txcnt, &iface->super, send_flags & IBV_SEND_SIGNALED);
    return;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_post_send_desc(uct_rc_verbs_ep_t* ep, struct ibv_send_wr *wr,
                                  uct_rc_iface_send_desc_t *desc, int send_flags,
                                  int max_log_sge, int is_oneside)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    UCT_RC_VERBS_FILL_DESC_WR(wr, desc);
    uct_rc_failover_ep_post_send(iface, ep, wr, send_flags, max_log_sge);
    uct_rc_failover_add_send_op_sn(ep, &desc->super, ep->txcnt.pi, is_oneside);
    return;
}

/* one-side */
static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_add_fo_send_comp(uct_rc_iface_t *iface, uct_rc_verbs_ep_t *ep, uct_rc_buf_info_t *buf_info,
                                    uct_rc_send_handler_t handler, uct_completion_t *comp,
                                    uint16_t sn, uint16_t flags, const uct_iov_t *iov,
                                    size_t iovcnt, size_t length, uint64_t raddr, unsigned opcode)
{
    uct_rc_iface_send_op_t *op;
    uint16_t i;

    op            = uct_rc_iface_get_send_op(iface);
    op->handler   = handler;
    op->user_comp = comp;
    op->flags    |= flags;
    op->length    = length;
    op->buf_info  = buf_info;
    if (op->flags & UCT_RC_IFACE_SEND_OP_FLAG_IOV) {
        /* coverity[dead_error_line] */
        uct_rc_ep_send_op_set_iov(op, iov, iovcnt);
    }
    uct_rc_failover_add_send_op_sn(ep, op, sn, 1);  // one side
    if (opcode == IBV_WR_RDMA_WRITE) {
        op->buf_info->op_type = UCT_EP_OP_PUT_ZCOPY;
    } else if (opcode == IBV_WR_RDMA_READ) {
        op->buf_info->op_type = UCT_EP_OP_GET_ZCOPY;
    } else {
        ucs_warn("invalid opcode %u when zcopy", opcode);
    }

    for (i = 0; i < iovcnt; i++) {
        op->buf_info->zcopy.iov[i] = iov[i];    // memcpy
    }
    op->buf_info->zcopy.iovcnt = iovcnt;
    op->buf_info->zcopy.remote_addr = raddr;
    return;
}

static inline ucs_status_t
uct_rc_failover_ep_rdma_zcopy(uct_rc_verbs_ep_t *ep, const uct_iov_t *iov,
                           size_t iovcnt, size_t iov_total_length,
                           uint64_t remote_addr, uct_rkey_t rkey,
                           uct_completion_t *comp, uct_rc_send_handler_t handler,
                           uint16_t op_flags, int opcode)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    struct ibv_sge sge[UCT_IB_MAX_IOV];
    struct ibv_send_wr wr;
    size_t sge_cnt;
    uct_rc_buf_info_t *buf_info;

    ucs_assertv(iovcnt <= ucs_min(UCT_IB_MAX_IOV, iface->config.max_send_sge),
                "iovcnt %zu, maxcnt (%zu, %zu)",
                iovcnt, UCT_IB_MAX_IOV, iface->config.max_send_sge);

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    sge_cnt = uct_ib_verbs_sge_fill_iov(sge, iov, iovcnt);
    /* cppcheck-suppress syntaxError */
    UCT_SKIP_ZERO_LENGTH(sge_cnt);
    UCT_RC_VERBS_FILL_RDMA_WR_IOV(wr, wr.opcode, (enum ibv_wr_opcode)opcode,
                                  sge, sge_cnt, remote_addr, rkey);
    wr.next = NULL;
    buf_info = uct_rc_failover_get_buf_info(iface);
    if (!buf_info) {
        return UCS_ERR_NO_RESOURCE;
    }

    uct_rc_failover_ep_post_send(iface, ep, &wr, IBV_SEND_SIGNALED, INT_MAX);
    uct_rc_failover_ep_add_fo_send_comp(&iface->super, ep, buf_info, handler, comp,
                                        ep->txcnt.pi, op_flags | UCT_RC_IFACE_SEND_OP_FLAG_ZCOPY,
                                        iov, iovcnt, iov_total_length, remote_addr, opcode);
    uct_rc_failover_oscnt_posted(ep);
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_failover_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                          unsigned length, uint64_t remote_addr,
                                          uct_rkey_t rkey)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep    = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("put short error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("put short error because of ep failover");
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(!iface->super.tx.in_pending && !ucs_arbiter_group_is_empty(&ep->super.arb_group))) {
        /* arbiter group not empty, we just need to add it to the arbiter again */
        ucs_info("put short error because arbiter group not empty");
        return UCS_ERR_BUSY;
    }

    UCT_CHECK_LENGTH(length, 0, iface->config.max_inline, "put_short");

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_FO_GET_TX_PUT_SHORT_DESC(&iface->super, &ucs_derived_of(iface, uct_rc_failover_iface_t)->inl_mp,
                                          desc, buffer, length);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_PUT_SHORT;
    desc->super.buf_info->rdma.length = length;
    desc->super.buf_info->rdma.remote_addr = remote_addr;
    uct_rc_failover_ep_fence_put(iface, ep, &rkey, &remote_addr);
    UCT_RC_VERBS_FILL_INL_PUT_WR(iface, remote_addr, rkey, buffer, length);
    UCT_TL_EP_STAT_OP(&ep->super.super, PUT, SHORT, length);
    uct_rc_failover_ep_post_send(iface, ep, &iface->inl_rwrite_wr,
                                 IBV_SEND_INLINE | IBV_SEND_SIGNALED, INT_MAX);
    uct_rc_failover_add_send_op_sn(ep, &desc->super, ep->txcnt.pi, 1 /* one side */);
    uct_rc_ep_enable_flush_remote(&ep->super);
    uct_rc_failover_oscnt_posted(ep);
    return UCS_OK;
}

ssize_t uct_rc_failover_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                     void *arg, uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc;
    struct ibv_send_wr wr;
    struct ibv_sge sge;
    size_t length;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("put bcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("put bcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_FO_GET_TX_PUT_BCOPY_DESC(&iface->super, &iface->super.tx.mp, desc,
                                          pack_cb, arg, length);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_PUT_BCOPY;
    desc->super.buf_info->rdma.length = length;
    desc->super.buf_info->rdma.remote_addr = remote_addr;
    uct_rc_failover_ep_fence_put(iface, ep, &rkey, &remote_addr);
    UCT_RC_VERBS_FILL_RDMA_WR(wr, wr.opcode, IBV_WR_RDMA_WRITE, sge,
                              length, remote_addr, rkey);
    UCT_TL_EP_STAT_OP(&ep->super.super, PUT, BCOPY, length);
    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, IBV_SEND_SIGNALED, INT_MAX, 1);
    uct_rc_ep_enable_flush_remote(&ep->super);
    uct_rc_failover_oscnt_posted(ep);
    return length;
}

ucs_status_t uct_rc_failover_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface,
                                                 uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    ucs_status_t status;
    size_t total_length         = uct_iov_total_length(iov, iovcnt);

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("put zcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("put zcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }

    UCT_CHECK_IOV_SIZE(iovcnt, iface->config.max_send_sge,
                       "uct_rc_verbs_ep_put_zcopy");
    uct_rc_failover_ep_fence_put(iface, ep, &rkey, &remote_addr);
    status = uct_rc_failover_ep_rdma_zcopy(ep, iov, iovcnt, total_length, remote_addr, rkey,
                                           comp, uct_rc_fo_send_op_completion_handler,
                                           0, IBV_WR_RDMA_WRITE);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, &ep->super.super, PUT, ZCOPY,
                                 uct_iov_total_length(iov, iovcnt));
    uct_rc_ep_enable_flush_remote(&ep->super);
    return status;
}

ucs_status_t uct_rc_failover_ep_get_bcopy(uct_ep_h tl_ep,
                                          uct_unpack_callback_t unpack_cb,
                                          void *arg, size_t length,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc;
    struct ibv_send_wr wr;
    struct ibv_sge sge;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("get bcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("get bcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }

    UCT_CHECK_LENGTH(length, 0, iface->super.super.config.seg_size, "get_bcopy");
    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_FO_GET_TX_GET_BCOPY_DESC(&iface->super, &iface->super.tx.mp, desc,
                                          unpack_cb, comp, arg, length);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_GET_BCOPY;
    desc->super.buf_info->rdma.remote_addr = remote_addr;
    UCT_RC_VERBS_FILL_RDMA_WR(wr, wr.opcode, IBV_WR_RDMA_READ, sge, length, remote_addr,
                              uct_ib_md_direct_rkey(rkey));

    UCT_TL_EP_STAT_OP(&ep->super.super, GET, BCOPY, length);
    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, IBV_SEND_SIGNALED, INT_MAX, 1 /* one side */);
    UCT_RC_RDMA_READ_POSTED(&iface->super, length);
    uct_rc_failover_oscnt_posted(ep);
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_failover_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                          size_t iovcnt, uint64_t remote_addr,
                                          uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface  = ucs_derived_of(tl_ep->iface,
                                                  uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep  = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep        = &fo_ep->super;
    size_t total_length          = uct_iov_total_length(iov, iovcnt);
    ucs_status_t status;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("get zcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("get zcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }

    UCT_CHECK_IOV_SIZE(iovcnt, iface->config.max_send_sge,
                       "uct_rc_verbs_ep_get_zcopy");
    UCT_CHECK_LENGTH(total_length,
                     iface->super.super.config.max_inl_cqe[UCT_IB_DIR_TX] + 1,
                     iface->super.config.max_get_zcopy, "get_zcopy");

    status = uct_rc_failover_ep_rdma_zcopy(ep, iov, iovcnt, total_length, remote_addr,
                                           uct_ib_md_direct_rkey(rkey), comp,
                                           uct_rc_fo_get_zcopy_handler,
                                           UCT_RC_IFACE_SEND_OP_FLAG_IOV,
                                           IBV_WR_RDMA_READ);
    if (!UCS_STATUS_IS_ERR(status)) {
        UCT_RC_RDMA_READ_POSTED(&iface->super, total_length);
        UCT_TL_EP_STAT_OP(&ep->super.super, GET, ZCOPY, total_length);
    }
    return status;
}

ucs_status_t uct_rc_failover_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                         const void *buffer, unsigned length)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc = NULL;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("ep %p am short error because of failover", ep);
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("ep %p am short error because of ep failover", ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(!(ep->super.flags & UCT_RC_EP_FLAG_CONNECTED))) {
        /* when fault during aux connect, some lanes may switch before connected */
        return UCS_ERR_BUSY;
    }

    if (ucs_unlikely(!iface->super.tx.in_pending && !ucs_arbiter_group_is_empty(&ep->super.arb_group))) {
        /* arbiter group not empty, we just need to add it to the arbiter again */
        ucs_info("am short error because arbiter group not empty");
        return UCS_ERR_BUSY;
    }

    UCT_RC_CHECK_AM_SHORT(id, length, uct_rc_am_short_hdr_t, iface->config.max_inline);
    UCT_RC_CHECK_RES_AND_FC(&iface->super, &ep->super, id);
    uct_rc_verbs_iface_fill_inl_am_sge(iface, id, hdr, buffer, length);
    UCT_RC_IFACE_FO_GET_TX_AM_SHORT_DESC(&iface->super, &ucs_derived_of(iface, uct_rc_failover_iface_t)->inl_mp, desc,
                                         &iface->am_inl_hdr, uct_rc_am_short_hdr_t,
                                         buffer, length);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_AM_SHORT;
    desc->super.buf_info->bcopy.length = length + sizeof(uct_rc_am_short_hdr_t) - sizeof(uct_rc_hdr_t);
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, SHORT, sizeof(hdr) + length);
    uct_rc_failover_ep_post_send(iface, ep, &iface->inl_am_wr,
                                 IBV_SEND_INLINE | IBV_SEND_SOLICITED, INT_MAX);
    UCT_RC_UPDATE_FC(&ep->super, id);
    uct_rc_failover_add_send_op_sn(ep, &desc->super, ep->txcnt.pi, 0);        // push out_q

    return UCS_OK;
}

ucs_status_t uct_rc_failover_ep_am_short_iov(uct_ep_h tl_ep, uint8_t id,
                                             const uct_iov_t *iov, size_t iovcnt)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc = NULL;
    unsigned length;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("am short iov error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("am short iov error because of ep failover");
        return UCS_ERR_BUSY;
    }

    if (ucs_unlikely(!iface->super.tx.in_pending && !ucs_arbiter_group_is_empty(&ep->super.arb_group))) {
        /* arbiter group not empty, we just need to add it to the arbiter again */
        ucs_info("am short iov error because arbiter group not empty");
        return UCS_ERR_BUSY;
    }

    UCT_RC_CHECK_AM_SHORT(id, uct_iov_total_length(iov, iovcnt), uct_rc_hdr_t,
                          iface->config.max_inline);
    UCT_RC_CHECK_RES_AND_FC(&iface->super, &ep->super, id);
    UCT_CHECK_IOV_SIZE(iovcnt, UCT_IB_MAX_IOV - 1, "uct_rc_verbs_ep_am_short_iov");
    uct_rc_verbs_iface_fill_inl_am_sge_iov(iface, id, iov, iovcnt);
    UCT_RC_IFACE_FO_GET_TX_AM_SHORT_IOV_DESC(&iface->super, &ucs_derived_of(iface, uct_rc_failover_iface_t)->inl_mp,
                                             desc, &iface->am_inl_hdr.rc_hdr, uct_rc_hdr_t, &length, iov, iovcnt);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_AM_SHORT;
    desc->super.buf_info->bcopy.length = length;
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, SHORT, uct_iov_total_length(iov, iovcnt));
    uct_rc_failover_ep_post_send(iface, ep, &iface->inl_am_wr,
                                 IBV_SEND_INLINE | IBV_SEND_SOLICITED, INT_MAX);
    UCT_RC_UPDATE_FC(&ep->super, id);

    uct_rc_failover_add_send_op_sn(ep, &desc->super, ep->txcnt.pi, 0);        // push out_q

    return UCS_OK;
}

ssize_t uct_rc_failover_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                                    uct_pack_callback_t pack_cb, void *arg,
                                    unsigned flags)
{
    uct_rc_verbs_iface_t *iface         = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep         = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep               = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc      = NULL;
    struct ibv_send_wr wr;
    struct ibv_sge sge;
    size_t length;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("am bcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("am bcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(!(ep->super.flags & UCT_RC_EP_FLAG_CONNECTED))) {
        /* when fault during aux connect, ack need to be stucked */
        ucs_info("am bcopy error because of not connected");
        return UCS_ERR_BUSY;
    }

    if (ucs_unlikely(!iface->super.tx.in_pending && !ucs_arbiter_group_is_empty(&ep->super.arb_group))) {
        /* arbiter group not empty, we just need to add it to the arbiter again */
        ucs_info("am bcopy error because arbiter group not empty");
        return UCS_ERR_BUSY;
    }

    UCT_CHECK_AM_ID(id);

    UCT_RC_CHECK_RES_AND_FC(&iface->super, &ep->super, id);
    UCT_RC_IFACE_FO_GET_TX_AM_BCOPY_DESC(&iface->super, &iface->super.tx.mp, desc,
                                         id, uct_rc_am_hdr_fill, uct_rc_hdr_t,
                                         pack_cb, arg, &length);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_AM_BCOPY;
    desc->super.buf_info->bcopy.length = length;
    UCT_RC_VERBS_FILL_AM_BCOPY_WR(wr, sge, length + sizeof(uct_rc_hdr_t),
                                  wr.opcode);
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, BCOPY, length);
    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, IBV_SEND_SOLICITED, INT_MAX, 0);
    UCT_RC_UPDATE_FC(&ep->super, id);

    return length;
}

ucs_status_t uct_rc_failover_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                         unsigned header_length, const uct_iov_t *iov,
                                         size_t iovcnt, unsigned flags,
                                         uct_completion_t *comp)
{
    uct_rc_verbs_iface_t     *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep     = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep           = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc  = NULL;
    struct ibv_sge sge[UCT_IB_MAX_IOV]; /* First sge is reserved for the header */
    struct ibv_send_wr wr;
    int send_flags;
    size_t sge_cnt;
    int i;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("am zcopy error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("am zcopy error because of ep failover");
        return UCS_ERR_BUSY;
    }

    if (ucs_unlikely(!iface->super.tx.in_pending && !ucs_arbiter_group_is_empty(&ep->super.arb_group))) {
        /* arbiter group not empty, we just need to add it to the arbiter again */
        ucs_info("am zcopy error because arbiter group not empty");
        return UCS_ERR_BUSY;
    }

    /* 1 iov consumed by am header */
    UCT_CHECK_IOV_SIZE(iovcnt, iface->config.max_send_sge - 1,
                       "uct_rc_verbs_ep_am_zcopy");
    UCT_RC_CHECK_AM_ZCOPY(id, header_length, uct_iov_total_length(iov, iovcnt),
                          iface->config.short_desc_size,
                          iface->super.super.config.seg_size);
    UCT_RC_CHECK_RES_AND_FC(&iface->super, &ep->super, id);

    UCT_RC_IFACE_FO_GET_TX_AM_ZCOPY_DESC(&iface->super, &iface->short_desc_mp,
                                         desc, id, header, header_length, comp,
                                         &send_flags);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_AM_ZCOPY;
    desc->super.buf_info->zcopy.header_length = header_length;
    sge[0].length = sizeof(uct_rc_hdr_t) + header_length;
    sge_cnt = uct_ib_verbs_sge_fill_iov(sge + 1, iov, iovcnt);
    UCT_RC_VERBS_FILL_AM_ZCOPY_WR_IOV(wr, sge, (sge_cnt + 1), wr.opcode);
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, ZCOPY,
                      (header_length + uct_iov_total_length(iov, iovcnt)));
    UCT_RC_FO_AM_ZCOPY_DESC_FILL_IOV(desc, iov, iovcnt, i);
    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, send_flags | IBV_SEND_SOLICITED,
                                      UCT_IB_MAX_ZCOPY_LOG_SGE(&iface->super.super), 0);
    UCT_RC_UPDATE_FC(&ep->super, id);

    return UCS_INPROGRESS;
}

static void
uct_rc_failover_ep_atomic_post(uct_rc_verbs_ep_t *ep, int opcode, uint64_t compare_add,
                               uint64_t swap, uint64_t remote_addr, uct_rkey_t rkey,
                               uct_rc_iface_send_desc_t *desc, int force_sig)
{
    struct ibv_send_wr wr;
    struct ibv_sge sge;

    UCT_RC_VERBS_FILL_ATOMIC_WR(wr, wr.opcode, sge, (enum ibv_wr_opcode)opcode,
                                compare_add, swap, remote_addr,
                                uct_ib_md_direct_rkey(rkey));
    UCT_TL_EP_STAT_ATOMIC(&ep->super.super);
    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, force_sig, INT_MAX, 1);   // one-side
    uct_rc_ep_enable_flush_remote(&ep->super);
    uct_rc_failover_oscnt_posted(ep);
    return;
}

ucs_status_t uct_rc_failover_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode, uint64_t value,
                                              uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep       = &fo_ep->super;
    uct_rc_iface_send_desc_t *desc;

    if (opcode != UCT_ATOMIC_OP_ADD) {
        return UCS_ERR_UNSUPPORTED;
    }

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("atomic post error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("atomic post error because of ep failover");
        return UCS_ERR_BUSY;
    }

    /* TODO don't allocate descriptor - have dummy buffer */
    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_FO_GET_TX_ATOMIC_DESC(&iface->super, &iface->short_desc_mp, desc);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_ATOMIC_POST;
    desc->super.buf_info->atomic.opcode = opcode;
    desc->super.buf_info->atomic.compare_add = value;
    desc->super.buf_info->atomic.remote_addr = remote_addr;
    uct_rc_failover_ep_atomic_post(ep, IBV_WR_ATOMIC_FETCH_AND_ADD, value, 0,
                                   remote_addr, rkey, desc, IBV_SEND_SIGNALED);
    return UCS_OK;
}

static ucs_status_t
uct_rc_failover_ep_atomic(uct_rc_verbs_ep_t *ep, int opcode, void *result,
                       uint64_t compare_add, uint64_t swap, uint64_t remote_addr,
                       uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);
    uct_rc_iface_send_desc_t *desc;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_MIGRATING)) {
        ucs_info("atomic error because of failover");
        uct_rc_failover_ep_upcall(fo_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("atomic error because of ep failover");
        return UCS_ERR_BUSY;
    }

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_FO_GET_TX_ATOMIC_FETCH_DESC(&iface->super, &iface->short_desc_mp,
                                             desc, iface->super.config.atomic64_handler,
                                             result, comp);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.buf_info->op_type = UCT_EP_OP_ATOMIC_FETCH;
    desc->super.buf_info->atomic.opcode = opcode;
    desc->super.buf_info->atomic.compare_add = compare_add;
    desc->super.buf_info->atomic.swap = swap;
    desc->super.buf_info->atomic.remote_addr = remote_addr;
    uct_rc_failover_ep_atomic_post(ep, opcode, compare_add, swap, remote_addr,
                                   rkey, desc, IBV_SEND_SIGNALED |
                                   uct_rc_ep_fm(&iface->super, &ep->fi, IBV_SEND_FENCE));
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_failover_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                               uint64_t value, uint64_t *result,
                                               uint64_t remote_addr, uct_rkey_t rkey,
                                               uct_completion_t *comp)
{
    if (opcode != UCT_ATOMIC_OP_ADD) {
        return UCS_ERR_UNSUPPORTED;
    }

    return uct_rc_failover_ep_atomic(ucs_derived_of(tl_ep, uct_rc_verbs_ep_t),
                                     IBV_WR_ATOMIC_FETCH_AND_ADD, result, value, 0,
                                     remote_addr, rkey, comp);
}

ucs_status_t uct_rc_failover_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare, uint64_t swap,
                                               uint64_t remote_addr, uct_rkey_t rkey,
                                               uint64_t *result, uct_completion_t *comp)
{
    return uct_rc_failover_ep_atomic(ucs_derived_of(tl_ep, uct_rc_verbs_ep_t),
                                     IBV_WR_ATOMIC_CMP_AND_SWP, result, compare, swap,
                                     remote_addr, rkey, comp);
}

static void uct_rc_failover_ep_post_flush(uct_rc_verbs_ep_t *ep, int send_flags)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    struct ibv_send_wr wr;
    struct ibv_sge sge;
    int inl_flag;

    if (iface->config.flush_by_fc || (iface->config.max_inline == 0)) {
        /* Flush by flow control pure grant, in case the device does not
         * support 0-size RDMA_WRITE or does not support inline.
         */
        sge.addr   = (uintptr_t)(iface->fc_desc + 1);
        sge.length = sizeof(uct_rc_hdr_t);
        sge.lkey   = iface->fc_desc->lkey;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode  = IBV_WR_SEND;
        inl_flag   = 0;
    } else {
        /* Flush by empty RDMA_WRITE */
        wr.sg_list             = NULL;
        wr.num_sge             = 0;
        wr.opcode              = IBV_WR_RDMA_WRITE;
        wr.wr.rdma.remote_addr = 0;
        wr.wr.rdma.rkey        = 0;
        inl_flag               = IBV_SEND_INLINE;
    }
    wr.next = NULL;

    uct_rc_failover_oscnt_posted(ep);
    uct_rc_failover_ep_post_send(iface, ep, &wr, inl_flag | send_flags, 1);
    return;
}

static ucs_status_t
uct_rc_failover_ep_flush_remote(uct_rc_verbs_ep_t *ep, uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                 uct_rc_verbs_iface_t);
    uct_rc_iface_send_desc_t *desc;
    struct ibv_send_wr wr;
    struct ibv_sge sge;

    UCT_RC_CHECK_RES(&iface->super, &ep->super);

    UCT_RC_IFACE_GET_TX_DESC(iface, &iface->super.tx.mp, desc);
    desc->super.buf_info = uct_rc_failover_get_buf_info(iface);
    if (!desc->super.buf_info) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->super.handler   = uct_rc_fo_flush_remote_handler;
    desc->super.user_comp = comp;
    desc->super.buf_info->op_type = UCT_EP_OP_LAST;

    UCT_RC_VERBS_FILL_RDMA_WR(wr, wr.opcode, IBV_WR_RDMA_READ, sge,
                              UCT_IB_MD_FLUSH_REMOTE_LENGTH, 0,
                              ep->super.flush_rkey);

    uct_rc_failover_ep_post_send_desc(ep, &wr, desc, IBV_SEND_SIGNALED, INT_MAX, 1);
    ep->super.flags &= ~UCT_RC_EP_FLAG_FLUSH_REMOTE;
    uct_rc_failover_oscnt_posted(ep);
    return UCS_INPROGRESS;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_rc_failover_ep_add_fo_flush_comp(uct_rc_iface_t *iface, uct_rc_verbs_ep_t *ep,
                                     uct_completion_t *comp, uint16_t sn, int is_oneside)
{
    uct_rc_iface_send_op_t *op;

    if (comp != NULL) {
        op = (uct_rc_iface_send_op_t*)ucs_mpool_get(&iface->tx.send_op_mp);
        if (ucs_unlikely(op == NULL)) {
            ucs_error("Failed to allocate flush completion");
            return UCS_ERR_NO_MEMORY;
        }
        op->buf_info = uct_rc_failover_get_buf_info(ucs_derived_of(iface, uct_rc_verbs_iface_t));
        if (!op->buf_info) {
            ucs_mpool_put(op);
            return UCS_ERR_NO_RESOURCE;
        }

        uct_rc_ep_init_send_op(op, 0, comp, uct_rc_fo_flush_op_completion_handler);
        uct_rc_iface_send_op_set_name(op, "rc_txqp_add_flush_comp");
        op->iface = iface;
        uct_rc_failover_add_send_op_sn(ep, op, sn, is_oneside);
        op->buf_info->op_type = UCT_EP_OP_LAST;  // no need to handle
    }
    UCT_TL_EP_STAT_FLUSH_WAIT(&ep->super.super);
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_failover_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                      uct_completion_t *comp)
{
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_verbs_ep_t *ep       = ucs_derived_of(tl_ep, uct_rc_verbs_ep_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    int already_canceled        = ep->super.flags & UCT_RC_EP_FLAG_FLUSH_CANCEL;
    ucs_status_t status;

    UCT_CHECK_PARAM(!ucs_test_all_flags(flags, UCT_FLUSH_FLAG_CANCEL |
                                               UCT_FLUSH_FLAG_REMOTE),
                    "flush flags CANCEL and REMOTE are mutually exclusive");

    if (flags & UCT_FLUSH_FLAG_REMOTE) {
        UCT_RC_IFACE_CHECK_FLUSH_REMOTE(
                uct_ib_md_is_flush_rkey_valid(ep->super.flush_rkey), ep,
                &iface->super, rcv);
        if (ep->super.flags & UCT_RC_EP_FLAG_FLUSH_REMOTE) {
            if (ucs_unlikely(fo_ep->fault_flag)) {
                if (fo_ep->fault_flag == EP_FO_FLAG_FAULT) {
                    return UCS_OK;         // OK
                }
                /* DEV_FO_FLAG_IN_PROGRESS */
                ucs_info("iface %p ep %p flush error because of ep failover", iface, tl_ep);
                return UCS_ERR_BUSY;
            }
            if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_IN_PROGRESS)) {
                ucs_info("iface %p ep %p flush error because of failover", iface, tl_ep);
                return UCS_ERR_BUSY;
            }
            return uct_rc_failover_ep_flush_remote(ep, comp);
        }
    }

    if (ucs_unlikely(fo_ep->fault_flag)) {
        if (fo_ep->fault_flag == EP_FO_FLAG_FAULT) {
            return UCS_OK;         // OK
        }
        /* DEV_FO_FLAG_IN_PROGRESS */
        ucs_info("iface %p ep %p flush error because of ep failover", iface, tl_ep);
        return UCS_ERR_BUSY;
    }
    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_IN_PROGRESS)) {
        ucs_info("iface %p ep %p flush error because of failover", iface, tl_ep);
        return UCS_ERR_BUSY;
    }

    status = uct_rc_ep_flush(&ep->super, iface->config.tx_max_wr, flags);
    if (status != UCS_INPROGRESS) {
        return status;
    }

    if (uct_rc_txqp_unsignaled(&ep->super.txqp) != 0) {
        UCT_RC_CHECK_RES(&iface->super, &ep->super);
        uct_rc_failover_ep_post_flush(ep, IBV_SEND_SIGNALED);
    }

    if (ucs_unlikely((flags & UCT_FLUSH_FLAG_CANCEL) && !already_canceled)) {
        status = uct_ib_modify_qp(ep->qp, IBV_QPS_ERR);
        if (status != UCS_OK) {
            return status;
        }
    }

    if (!comp) {
        uct_rc_failover_ep_fill_outstanding(ep);
    }

    return uct_rc_failover_ep_add_fo_flush_comp(&iface->super, ep, comp, ep->txcnt.pi, 1);
}

void uct_rc_failover_ep_post_check(uct_ep_h tl_ep)
{
    uct_rc_verbs_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_verbs_ep_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_verbs_iface_t);
    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_IN_PROGRESS)) {
        ucs_info("iface %p ep %p post check error because of failover", iface, tl_ep);
        return;         // OK
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("iface %p ep %p post check error because of ep failover", iface, tl_ep);
        return;         // OK
    }

    uct_rc_failover_ep_post_flush(ep, 0);
    uct_rc_failover_ep_fill_outstanding(ep);
    return;
}

ucs_status_t uct_rc_failover_ep_fc_ctrl(uct_ep_t *tl_ep, unsigned op,
                                        uct_rc_pending_req_t *req)
{
    struct ibv_send_wr fc_wr;
    uct_rc_verbs_iface_t *iface = ucs_derived_of(tl_ep->iface,
                                                 uct_rc_verbs_iface_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    uct_rc_verbs_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_verbs_ep_t);
    uct_rc_hdr_t *hdr;
    struct ibv_sge sge;
    int flags;

    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super.super) >= DEV_FO_FLAG_IN_PROGRESS)) {
        ucs_info("iface %p ep %p fc ctrl error because of failover", iface, tl_ep);
        return UCS_OK;         // OK
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        ucs_info("iface %p ep %p fc ctrl error because of ep failover", iface, tl_ep);
        return UCS_OK;         // OK
    }

    if (!iface->fc_desc) {
        hdr                      = &iface->am_inl_hdr.rc_hdr;
        hdr->am_id               = UCT_RC_EP_FC_PURE_GRANT;
        fc_wr.sg_list            = iface->inl_sge;
        iface->inl_sge[0].addr   = (uintptr_t)hdr;
        iface->inl_sge[0].length = sizeof(*hdr);
        flags                    = IBV_SEND_INLINE;
    } else {
        hdr           = (uct_rc_hdr_t*)(iface->fc_desc + 1);
        sge.addr      = (uintptr_t)hdr;
        sge.length    = sizeof(*hdr);
        sge.lkey      = iface->fc_desc->lkey;
        fc_wr.sg_list = &sge;
        flags         = 0;
    }

    /* In RC only PURE grant is sent as a separate message. Other FC
     * messages are bundled with AM. */
    ucs_assert(op == UCT_RC_EP_FC_PURE_GRANT);

    /* Do not check FC WND here to avoid head-to-head deadlock.
     * Credits grant should be sent regardless of FC wnd state. */
    UCT_RC_CHECK_TX_CQ_RES(&iface->super, &ep->super);

    fc_wr.opcode  = IBV_WR_SEND;
    fc_wr.next    = NULL;
    fc_wr.num_sge = 1;

    uct_rc_failover_ep_post_send(iface, ep, &fc_wr, flags, INT_MAX);
    uct_rc_failover_ep_fill_outstanding(ep);
    uct_rc_failover_oscnt_posted(ep);
    return UCS_OK;
}

ucs_status_t uct_rc_failover_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                            unsigned flags)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_ep_t);
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);

    /* If fault, both the ep and iface resources are free,
     * so we need to skip the following determination
     * and allow req to go directly to the pending queue.
     */
    if (ucs_unlikely(uct_ib_check_iface_fault_flag(&iface->super) >= DEV_FO_FLAG_IN_PROGRESS)) {
        goto add_req;
    }
    if (ucs_unlikely(fo_ep->fault_flag)) {
        goto add_req;
    }

    if (ucs_unlikely(!iface->tx.in_pending && !ucs_arbiter_group_is_empty(&ep->arb_group))) {
        goto add_req;
    }

    if (uct_rc_ep_has_tx_resources(ep) &&
        uct_rc_iface_has_tx_resources(iface)) {
        return UCS_ERR_BUSY;
    }

add_req:
    UCS_STATIC_ASSERT(sizeof(uct_pending_req_priv_arb_t) <=
                      UCT_PENDING_REQ_PRIV_LEN);
    uct_pending_req_arb_group_push(&ep->arb_group, n);
    UCT_TL_EP_STAT_PEND(&ep->super);

    if (uct_rc_ep_has_tx_resources(ep)) {
        /* If we have ep (but not iface) resources, we need to schedule the ep */
        ucs_arbiter_group_schedule(&iface->tx.arbiter, &ep->arb_group);
    }

    return UCS_OK;
}

ucs_status_t
uct_rc_failover_ep_get_private_data(uct_ep_h tl_ep, uint64_t *private_data)
{
    uct_rc_failover_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_failover_ep_t);
    *private_data = ep->rxcnt.ack;
    return UCS_OK;
}

ucs_status_t uct_rc_failover_pre_handle(uct_ep_h origin_ep)
{
    unsigned count = 0;
    uct_rc_verbs_iface_t *iface = ucs_derived_of(origin_ep->iface, uct_rc_verbs_iface_t);
    uct_rc_verbs_ep_t *ep       = ucs_derived_of(origin_ep, uct_rc_verbs_ep_t);
    // poll tx
    count += uct_rc_verbs_iface_simply_poll_tx(iface);
    // poll rx
    count += uct_rc_verbs_iface_simply_poll_rx(iface);

    ucs_info("failover iface %p pre handle %u", iface, count);

    if (count == 0) {
        (void)uct_ib_modify_qp(ep->qp, IBV_QPS_ERR);    /* stop dev */
    }

    return count > 0 ? UCS_ERR_BUSY : UCS_OK;
}

void uct_rc_failover_set_fault(uct_ep_h origin_ep, uct_ep_fault_status_t status)
{
    uct_rc_failover_ep_t *ep = ucs_derived_of(origin_ep, uct_rc_failover_ep_t);
    ep->fault_flag = status;
}

static UCS_F_ALWAYS_INLINE void uct_rc_failover_oscnt_init(uct_rc_failover_oscnt_t *oscnt)
{
    oscnt->tx_pc = oscnt->tx_cc = 0;
}

static UCS_F_ALWAYS_INLINE void uct_rc_failover_rxcnt_init(uct_rc_failover_rxcnt_t *rxcnt)
{
    rxcnt->ack = 0;
}

static void
uct_rc_failover_purge_oustanding_os(uct_rc_failover_ep_t *self)
{
    uct_rc_iface_send_op_t *op;
    ucs_queue_for_each_extract(op, &self->outstanding_os, queue, 1) {
        uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
    }
    return;
}

UCS_CLASS_INIT_FUNC(uct_rc_failover_ep_t, const uct_ep_params_t *params)
{
    UCS_CLASS_CALL_SUPER_INIT(uct_rc_verbs_ep_t, params);
    uct_rc_failover_oscnt_init(&self->oscnt);
    uct_rc_failover_rxcnt_init(&self->rxcnt);
    self->fo_resend_prepare_flag = 0;
    self->fault_flag = 0;
    ucs_queue_head_init(&self->outstanding_os);
    self->prog_id = UCS_CALLBACKQ_ID_NULL;
    return UCS_OK;
}

UCS_CLASS_CLEANUP_FUNC(uct_rc_failover_ep_t)
{
    uct_rc_failover_purge_oustanding_os(self);
    ucs_assert(ucs_queue_is_empty(&self->outstanding_os));
    return;
}

UCS_CLASS_DEFINE(uct_rc_failover_ep_t, uct_rc_verbs_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_rc_failover_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_rc_failover_ep_t, uct_ep_t);
