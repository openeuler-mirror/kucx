/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#ifndef UCT_RC_FAILOVER_H
#define UCT_RC_FAILOVER_H

#include <uct/api/uct_def.h>
#include <uct/api/v2/uct_v2.h>
#include <ucs/type/status.h>
#include <ucs/datastruct/arbiter.h>

#include "rc_iface.h"

void uct_rc_set_iface_fault_flag(uct_iface_h iface, unsigned status);

void uct_rc_ep_failover_pending_transfer_progress(uct_ep_h origin_ep, uct_ep_h new_ep);

ucs_arbiter_cb_result_t
uct_rc_failover_ep_process_pending(ucs_arbiter_t *arbiter,
                                   ucs_arbiter_group_t *group,
                                   ucs_arbiter_elem_t *elem,
                                   void *arg);

static inline void
uct_rc_fo_send_handler(uct_rc_iface_send_op_t *op, const void *resp)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    ucs_mpool_put(desc->super.buf_info);
    ucs_mpool_put(desc);
}

#define UCT_RC_IFACE_FO_GET_TX_AM_SHORT_DESC(_iface, _mp, _desc, _hdr_addr, _hdr, \
                                             _buffer, _length) ({ \
    _hdr *rch; \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    (_desc)->super.handler = uct_rc_fo_send_handler; \
    rch = (_hdr *)(_desc + 1); \
    memcpy(rch, _hdr_addr, sizeof(_hdr)); \
    memcpy(rch + 1, _buffer, _length); \
})

static UCS_F_ALWAYS_INLINE size_t
uct_rc_iov_to_buffer(void *buff, const uct_iov_t *iov, size_t iovcnt)
{
    ucs_iov_iter_t iov_iter;
    ucs_iov_iter_init(&iov_iter);
    return uct_iov_to_buffer(iov, iovcnt, &iov_iter, buff, SIZE_MAX);
}

#define UCT_RC_IFACE_FO_GET_TX_AM_SHORT_IOV_DESC(_iface, _mp, _desc, _hdr_addr, _hdr, \
                                                 _length, _iov, _iovcnt) ({ \
    _hdr *rch; \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    (_desc)->super.handler = uct_rc_fo_send_handler; \
    rch = (_hdr *)(_desc + 1); \
    memcpy(rch, _hdr_addr, sizeof(_hdr)); \
    *(_length) = uct_rc_iov_to_buffer(rch + 1, _iov, _iovcnt); \
})

#define UCT_RC_IFACE_FO_GET_TX_AM_BCOPY_DESC(_iface, _mp, _desc, _id, _pk_hdr_cb, \
                                             _hdr, _pack_cb, _arg, _length) ({ \
    _hdr *rch; \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    (_desc)->super.handler = uct_rc_fo_send_handler; \
    rch = (_hdr *)(_desc + 1); \
    _pk_hdr_cb(rch, _id); \
    *(_length) = _pack_cb(rch + 1, _arg); \
})

static inline void
uct_rc_fo_am_zcopy_handler(uct_rc_iface_send_op_t *op, const void *resp)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    uct_invoke_completion(desc->super.user_comp, UCS_OK);
    ucs_mpool_put(desc->super.buf_info);
    ucs_mpool_put(desc);
}

static inline void
uct_rc_fo_zcopy_desc_set_comp(uct_rc_iface_send_desc_t *desc,
                              uct_completion_t *comp,
                              int *send_flags)
{
    if (comp == NULL) {
        desc->super.handler   = uct_rc_fo_send_handler;
        *send_flags           = 0;
    } else {
        desc->super.handler   = uct_rc_fo_am_zcopy_handler;
        desc->super.user_comp = comp;
        *send_flags           = IBV_SEND_SIGNALED;
    }
}

#define UCT_RC_IFACE_FO_GET_TX_AM_ZCOPY_DESC(_iface, _mp, _desc, \
                                             _id, _header, _header_length, _comp, _send_flags) \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc); \
    uct_rc_fo_zcopy_desc_set_comp(_desc, _comp, _send_flags); \
    uct_rc_zcopy_desc_set_header((uct_rc_hdr_t*)(_desc + 1), _id, _header, _header_length);

#define UCT_RC_FO_AM_ZCOPY_DESC_FILL_IOV(_desc, _iov, _iovcnt, _i) \
    for (_i = 0; _i < _iovcnt; i++) {   \
        (_desc)->super.buf_info->zcopy.iov[i] = _iov[i];  \
    }   \
    (_desc)->super.buf_info->zcopy.iovcnt = _iovcnt;

static inline void
uct_rc_fo_send_op_completion_handler(uct_rc_iface_send_op_t *op,
                                     const void *resp)
{
    if (op->user_comp) {
        uct_invoke_completion(op->user_comp, UCS_OK);
    }
    ucs_mpool_put(op->buf_info);
    uct_rc_iface_put_send_op(op);
}

static inline void
uct_rc_fo_op_release_get_bcopy(uct_rc_iface_send_op_t *op)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);
    uct_rc_iface_t          *iface = ucs_container_of(ucs_mpool_obj_owner(desc),
                                                      uct_rc_iface_t, tx.mp);

    iface->tx.reads_completed += op->length;
}

static inline void
uct_rc_fo_get_bcopy_handler(uct_rc_iface_send_op_t *op, const void *resp)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);

    VALGRIND_MAKE_MEM_DEFINED(resp, desc->super.length);

    desc->unpack_cb(desc->super.unpack_arg, resp, desc->super.length);

    uct_rc_fo_op_release_get_bcopy(op);
    if (desc->super.user_comp) {
        uct_invoke_completion(desc->super.user_comp, UCS_OK);
    }
    ucs_mpool_put(desc->super.buf_info);
    ucs_mpool_put(desc);
}

static void
uct_rc_fo_send_op_completed_iov(uct_rc_iface_send_op_t *op)
{
#ifndef NVALGRIND
    struct iovec *iov_entry = op->iov;
    size_t length           = 0;

    ucs_assert(op->flags & UCT_RC_IFACE_SEND_OP_FLAG_IOV);

    if (iov_entry == NULL) {
        return;
    }

    while (length < op->length) {
        /* The memory might not be HOST */
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(iov_entry->iov_base,
                                                 iov_entry->iov_len);
        length += iov_entry->iov_len;
        ++iov_entry;
    }

    ucs_free(op->iov);
    op->iov = NULL;
#endif
}

static inline void
uct_rc_fo_op_release_get_zcopy(uct_rc_iface_send_op_t *op)
{
    op->iface->tx.reads_completed += op->length;

    if (RUNNING_ON_VALGRIND) {
        uct_rc_fo_send_op_completed_iov(op);
    }

    op->flags &= ~UCT_RC_IFACE_SEND_OP_FLAG_IOV;
}

static inline void
uct_rc_fo_get_zcopy_handler(uct_rc_iface_send_op_t *op,
                            const void *resp)
{
    uct_rc_fo_op_release_get_zcopy(op);
    uct_rc_fo_send_op_completion_handler(op, resp);
}

static inline void
uct_rc_fo_flush_remote_handler(uct_rc_iface_send_op_t *op,
                               const void *resp)
{
    uct_rc_iface_send_desc_t *desc = ucs_derived_of(op, uct_rc_iface_send_desc_t);

    if (desc->super.user_comp) {
        uct_invoke_completion(desc->super.user_comp, UCS_OK);
    }
    ucs_mpool_put(desc->super.buf_info);
    ucs_mpool_put(desc);
}

static inline void
uct_rc_fo_flush_op_completion_handler(uct_rc_iface_send_op_t *op, const void *resp)
{
    uct_invoke_completion(op->user_comp, UCS_OK);
    ucs_mpool_put(op->buf_info);
    ucs_mpool_put(op);
}

#define UCT_RC_IFACE_FO_GET_TX_PUT_SHORT_DESC(_iface, _mp, _desc, _buffer, _length) ({ \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    (_desc)->super.handler = uct_rc_fo_send_handler; \
    memcpy(_desc + 1, _buffer, _length); \
})

#define UCT_RC_IFACE_FO_GET_TX_PUT_BCOPY_DESC(_iface, _mp, _desc, _pack_cb, _arg, _length) \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    (_desc)->super.handler = uct_rc_fo_send_handler; \
    _length = _pack_cb(_desc + 1, _arg); \
    UCT_SKIP_ZERO_LENGTH(_length, _desc);

#define UCT_RC_IFACE_FO_GET_TX_GET_BCOPY_DESC(_iface, _mp, _desc, _unpack_cb, _comp, _arg, _length) \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    ucs_assert(_length <= (_iface)->super.config.seg_size); \
    _desc->super.handler     = uct_rc_fo_get_bcopy_handler; \
    _desc->super.unpack_arg  = _arg; \
    _desc->super.user_comp   = _comp; \
    _desc->super.length      = _length; \
    _desc->unpack_cb         = _unpack_cb;

#define UCT_RC_IFACE_FO_GET_TX_ATOMIC_DESC(_iface, _mp, _desc) \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    _desc->super.handler = (uct_rc_send_handler_t)uct_rc_fo_send_handler;

#define UCT_RC_IFACE_FO_GET_TX_ATOMIC_FETCH_DESC(_iface, _mp, _desc, _handler, _result, _comp) \
    UCT_CHECK_PARAM(_comp != NULL, "completion must be non-NULL"); \
    UCT_RC_IFACE_GET_TX_DESC(_iface, _mp, _desc) \
    _desc->super.handler   = _handler; \
    _desc->super.buffer    = _result; \
    _desc->super.user_comp = _comp;

#endif  // UCT_RC_FAILOVER_H