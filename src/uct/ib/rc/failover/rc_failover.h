/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#ifndef UCT_RC_F_H
#define UCT_RC_F_H

#include <uct/ib/rc/base/rc_iface.h>
#include <uct/ib/rc/base/rc_ep.h>
#include <uct/ib/rc/verbs/rc_verbs.h>
#include <ucs/type/class.h>

/* for one-side count */
typedef struct uct_rc_failover_oscnt {
    uint16_t       tx_pc;   /* producer count */
    uint16_t       tx_cc;   /* consumer count */
} uct_rc_failover_oscnt_t;

/* recv-end two-side ack */
typedef struct uct_rc_failover_rxcnt {
    uint16_t       ack;
} uct_rc_failover_rxcnt_t;

/**
 * RC failover communication context.
 */
typedef struct uct_rc_failover_ep {
    uct_rc_verbs_ep_t           super;
    uct_rc_failover_oscnt_t     oscnt;        // one-side cnt for failover
    uct_rc_failover_rxcnt_t     rxcnt;
    int                         fo_resend_prepare_flag; // for failover resend prepare once
    ucs_queue_head_t            outstanding_os;     // one-sided outstandng_q
    uct_ep_fault_status_t       fault_flag;         // ep fault status
    uct_worker_cb_id_t          prog_id;            // ep failover prog id
} uct_rc_failover_ep_t;

/**
 * RC failover interface.
 */
typedef struct uct_rc_failover_iface {
    uct_rc_verbs_iface_t        super;
    ucs_mpool_t                 inl_mp;     /* for short buffer */
    ucs_mpool_t                 buf_info_mp;    /* for buf info */
} uct_rc_failover_iface_t;

static UCS_F_ALWAYS_INLINE uct_rc_buf_info_t*
uct_rc_failover_get_buf_info(uct_rc_verbs_iface_t *iface)
{
    uct_rc_failover_iface_t *fo_iface = ucs_derived_of(iface, uct_rc_failover_iface_t);
    uct_rc_buf_info_t *buf_info = (uct_rc_buf_info_t *)ucs_mpool_get(&fo_iface->buf_info_mp);
    if (ucs_unlikely(buf_info == NULL)) {
        ucs_error("failed to alloc buf info");
        return NULL;
    }
    return buf_info;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_failover_ep_completion_desc(uct_rc_verbs_ep_t *ep, uint16_t sn, uint16_t *tscnt)
{
    uct_rc_iface_send_op_t *op;
    uint16_t ts_cnt = 0;       // two-side count
    uct_rc_txqp_t *txqp = &ep->super.txqp;
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);

    ucs_trace_poll("txqp %p complete ops up to sn %d", txqp, sn);
    ucs_queue_for_each_extract(op, &txqp->outstanding, queue,
                               UCS_CIRCULAR_COMPARE16(op->sn, <=, sn)) {
        ts_cnt++;
        uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
    }
    // one-side
    ucs_queue_for_each_extract(op, &fo_ep->outstanding_os, queue,
                               UCS_CIRCULAR_COMPARE16(op->sn, <=, sn)) {
        uct_rc_txqp_completion_op(op, ucs_derived_of(op, uct_rc_iface_send_desc_t) + 1);
    }
    if (tscnt) {
        *tscnt = ts_cnt;
    }
    return;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_failover_oscnt_posted(uct_rc_verbs_ep_t* ep)
{
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);
    fo_ep->oscnt.tx_pc++;
    return;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_failover_oscnt_update(uct_rc_verbs_ep_t* ep, uint16_t os_cnt)
{
    uct_rc_failover_ep_t *fo_ep = ucs_derived_of(ep, uct_rc_failover_ep_t);
    fo_ep->oscnt.tx_cc += os_cnt;
    return;
}

unsigned uct_rc_verbs_iface_simply_poll_tx(uct_rc_verbs_iface_t *iface);
unsigned uct_rc_verbs_iface_simply_poll_rx(uct_rc_verbs_iface_t *iface);

UCS_CLASS_DECLARE(uct_rc_failover_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_NEW_FUNC(uct_rc_failover_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_rc_failover_ep_t, uct_ep_t);

ucs_status_t uct_rc_failover_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                          unsigned length, uint64_t remote_addr,
                                          uct_rkey_t rkey);

ssize_t uct_rc_failover_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                     void *arg, uint64_t remote_addr,
                                     uct_rkey_t rkey);

ucs_status_t uct_rc_failover_ep_put_zcopy(uct_ep_h tl_ep,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_get_bcopy(uct_ep_h tl_ep,
                                          uct_unpack_callback_t unpack_cb,
                                          void *arg, size_t length,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_get_zcopy(uct_ep_h tl_ep,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                         const void *buffer, unsigned length);

ucs_status_t uct_rc_failover_ep_am_short_iov(uct_ep_h ep, uint8_t id,
                                             const uct_iov_t *iov, size_t iovcnt);

ssize_t uct_rc_failover_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                                    uct_pack_callback_t pack_cb, void *arg,
                                    unsigned flags);

ucs_status_t uct_rc_failover_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                         unsigned header_length, const uct_iov_t *iov,
                                         size_t iovcnt, unsigned flags,
                                         uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare, uint64_t swap,
                                               uint64_t remote_addr, uct_rkey_t rkey,
                                               uint64_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode, uint64_t value,
                                              uint64_t remote_addr, uct_rkey_t rkey);

ucs_status_t uct_rc_failover_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                               uint64_t value, uint64_t *result,
                                               uint64_t remote_addr, uct_rkey_t rkey,
                                               uct_completion_t *comp);

ucs_status_t uct_rc_failover_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                      uct_completion_t *comp);

void uct_rc_failover_ep_post_check(uct_ep_h tl_ep);

ucs_status_t uct_rc_failover_ep_fc_ctrl(uct_ep_t *tl_ep, unsigned op,
                                        uct_rc_pending_req_t *req);

ucs_status_t uct_rc_failover_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n, unsigned flags);

ucs_status_t uct_rc_failover_ep_get_private_data(uct_ep_h tl_ep, uint64_t *private_data);

ucs_status_t uct_rc_failover_ep_failover_resend_progress(uct_ep_h origin_ep, uint64_t priv_data,
                                                         uct_ep_h new_ep, uct_rkey_ctx_t *rkey_ctx);

ucs_status_t uct_rc_failover_pre_handle(uct_ep_h origin_ep);

void uct_rc_failover_set_fault(uct_ep_h origin_ep, uct_ep_fault_status_t status);

#endif      // UCT_RC_F_H