/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "rc_mlx5.h"

#include <uct/ib/mlx5/ib_mlx5_log.h>
#include <ucs/arch/cpu.h>
#include <ucs/sys/compiler.h>
#include <arpa/inet.h> /* For htonl */

/*
 *
 * Helper function for buffer-copy post.
 * Adds the descriptor to the callback queue.
 */
static UCS_F_ALWAYS_INLINE void
uct_rc_mlx5_txqp_bcopy_post(uct_rc_iface_t *iface, uct_rc_txqp_t *txqp, uct_ib_mlx5_txwq_t *txwq,
                            unsigned opcode, unsigned length,
                            /* SEND */ uint8_t am_id, void *am_hdr, unsigned am_hdr_len,
                            /* RDMA */ uint64_t rdma_raddr, uct_rkey_t rdma_rkey,
                            int force_sig, uct_rc_iface_send_desc_t *desc)
{
    desc->super.sn = txwq->sw_pi;
    uct_rc_mlx5_txqp_dptr_post(iface, IBV_QPT_RC, txqp, txwq,
                               opcode, desc + 1, length, &desc->lkey,
                               am_id, am_hdr, am_hdr_len,
                               rdma_raddr, uct_ib_md_direct_rkey(rdma_rkey),
                               0, 0, 0,
                               NULL, 0, force_sig);
    uct_rc_txqp_add_send_op(txqp, &desc->super);
}

/*
 * Helper function for zero-copy post.
 * Adds user completion to the callback queue.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_rc_mlx5_ep_zcopy_post(uct_rc_mlx5_ep_t *ep,
                          unsigned opcode, const uct_iov_t *iov, size_t iovcnt,
                          /* SEND */ uint8_t am_id, const void *am_hdr, unsigned am_hdr_len,
                          /* RDMA */ uint64_t rdma_raddr, uct_rkey_t rdma_rkey,
                          int force_sig, uct_completion_t *comp)
{
    uct_rc_iface_t *iface  = ucs_derived_of(ep->super.super.super.iface,
                                            uct_rc_iface_t);
    uint16_t sn;

    UCT_RC_CHECK_RES(iface, &ep->super);

    sn = ep->tx.wq.sw_pi;
    uct_rc_mlx5_txqp_dptr_post_iov(iface, IBV_QPT_RC,
                                   &ep->super.txqp, &ep->tx.wq,
                                   opcode, iov, iovcnt,
                                   am_id, am_hdr, am_hdr_len,
                                   rdma_raddr, uct_ib_md_direct_rkey(rdma_rkey),
                                   NULL, 0,
                                   (comp == NULL) ? force_sig : MLX5_WQE_CTRL_CQ_UPDATE);

    uct_rc_txqp_add_send_comp(iface, &ep->super.txqp, comp, sn);
    return UCS_INPROGRESS;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_mlx5_ep_atomic_post(uct_rc_mlx5_ep_t *ep, unsigned opcode,
                           uct_rc_iface_send_desc_t *desc, unsigned length,
                           uint64_t remote_addr, uct_rkey_t rkey,
                           uint64_t compare_mask, uint64_t compare,
                           uint64_t swap_add, int signal)
{
    uct_rc_iface_t *iface  = ucs_derived_of(ep->super.super.super.iface,
                                            uct_rc_iface_t);
    uint32_t ib_rkey = uct_ib_resolve_atomic_rkey(rkey, ep->super.atomic_mr_offset,
                                                  &remote_addr);

    desc->super.sn = ep->tx.wq.sw_pi;
    uct_rc_mlx5_txqp_dptr_post(iface, IBV_QPT_RC,
                               &ep->super.txqp, &ep->tx.wq,
                               opcode, desc + 1, length, &desc->lkey,
                               0, NULL, 0, remote_addr, ib_rkey,
                               compare_mask, compare, swap_add,
                               NULL, 0, signal);

    UCT_TL_EP_STAT_ATOMIC(&ep->super.super);
    uct_rc_txqp_add_send_op(&ep->super.txqp, &desc->super);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_rc_mlx5_ep_atomic(uct_rc_mlx5_ep_t *ep, int opcode, void *result, int ext,
                      unsigned length, uint64_t remote_addr, uct_rkey_t rkey,
                      uint64_t compare_mask, uint64_t compare,
                      uint64_t swap_add, uct_completion_t *comp)
{
    uct_rc_mlx5_iface_t *iface = ucs_derived_of(ep->super.super.super.iface,
                                                uct_rc_mlx5_iface_t);
    uct_rc_iface_send_desc_t *desc;

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_GET_TX_ATOMIC_DESC(&iface->super, &iface->mlx5_common.tx.atomic_desc_mp, desc,
                                    uct_rc_iface_atomic_handler(&iface->super, ext, length),
                                    result, comp);
    uct_rc_mlx5_ep_atomic_post(ep, opcode, desc, length, remote_addr, rkey,
                               compare_mask, compare, swap_add,
                               MLX5_WQE_CTRL_CQ_UPDATE);
    return UCS_INPROGRESS;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_rc_mlx5_ep_atomic_add(uct_ep_h tl_ep, int opcode, unsigned length,
                          uint64_t add, uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_rc_mlx5_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_mlx5_iface_t);
    uct_rc_mlx5_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_iface_send_desc_t *desc;

    UCT_RC_CHECK_RES(&iface->super, &ep->super);
    UCT_RC_IFACE_GET_TX_ATOMIC_ADD_DESC(&iface->super, &iface->mlx5_common.tx.atomic_desc_mp, desc);

    uct_rc_mlx5_ep_atomic_post(ep, opcode, desc, length, remote_addr, rkey, 0,
                               0, add, 0);
    return UCS_OK;
}

ucs_status_t uct_rc_mlx5_ep_put_short(uct_ep_h tl_ep, const void *buffer, unsigned length,
                                      uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);

    UCT_RC_MLX5_CHECK_PUT_SHORT(length, 0);
    UCT_RC_CHECK_RES(iface, &ep->super);

    uct_rc_mlx5_txqp_inline_post(iface, IBV_QPT_RC,
                                 &ep->super.txqp, &ep->tx.wq,
                                 MLX5_OPCODE_RDMA_WRITE,
                                 buffer, length, 0, 0, 0,
                                 remote_addr, uct_ib_md_direct_rkey(rkey),
                                 NULL, 0);
    UCT_TL_EP_STAT_OP(&ep->super.super, PUT, SHORT, length);
    return UCS_OK;
}

ssize_t uct_rc_mlx5_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                 void *arg, uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_iface_send_desc_t *desc;
    size_t length;

    UCT_RC_CHECK_RES(iface, &ep->super);
    UCT_RC_IFACE_GET_TX_PUT_BCOPY_DESC(iface, &iface->tx.mp,
                                       desc, pack_cb, arg, length);

    uct_rc_mlx5_txqp_bcopy_post(iface, &ep->super.txqp, &ep->tx.wq,
                                MLX5_OPCODE_RDMA_WRITE, length, 0, NULL, 0,
                                remote_addr, rkey, MLX5_WQE_CTRL_CQ_UPDATE, desc);
    UCT_TL_EP_STAT_OP(&ep->super.super, PUT, BCOPY, length);
    return length;
}

ucs_status_t uct_rc_mlx5_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                      uint64_t remote_addr, uct_rkey_t rkey,
                                      uct_completion_t *comp)
{
    uct_ib_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ib_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    ucs_status_t status;

    UCT_CHECK_IOV_SIZE(iovcnt, uct_ib_iface_get_max_iov(iface),
                       "uct_rc_mlx5_ep_put_zcopy");
    UCT_CHECK_LENGTH(uct_iov_total_length(iov, iovcnt), 0, UCT_IB_MAX_MESSAGE_SIZE,
                     "put_zcopy");

    status = uct_rc_mlx5_ep_zcopy_post(ep, MLX5_OPCODE_RDMA_WRITE, iov, iovcnt,
                                       0, NULL, 0, remote_addr, rkey,
                                       MLX5_WQE_CTRL_CQ_UPDATE, comp);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, &ep->super.super, PUT, ZCOPY,
                                 uct_iov_total_length(iov, iovcnt));
    return status;
}

ucs_status_t uct_rc_mlx5_ep_get_bcopy(uct_ep_h tl_ep,
                                      uct_unpack_callback_t unpack_cb,
                                      void *arg, size_t length,
                                      uint64_t remote_addr, uct_rkey_t rkey,
                                      uct_completion_t *comp)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_iface_send_desc_t *desc;

    UCT_CHECK_LENGTH(length, 0, iface->super.config.seg_size, "get_bcopy");
    UCT_RC_CHECK_RES(iface, &ep->super);
    UCT_RC_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.mp, desc,
                                       unpack_cb, comp, arg, length);

    uct_rc_mlx5_txqp_bcopy_post(iface, &ep->super.txqp, &ep->tx.wq,
                                MLX5_OPCODE_RDMA_READ, length, 0, NULL, 0,
                                remote_addr, rkey, MLX5_WQE_CTRL_CQ_UPDATE, desc);
    UCT_TL_EP_STAT_OP(&ep->super.super, GET, BCOPY, length);
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_mlx5_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                      uint64_t remote_addr, uct_rkey_t rkey,
                                      uct_completion_t *comp)
{
    uct_ib_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ib_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    ucs_status_t status;

    UCT_CHECK_IOV_SIZE(iovcnt, uct_ib_iface_get_max_iov(iface),
                       "uct_rc_mlx5_ep_get_zcopy");
    UCT_CHECK_LENGTH(uct_iov_total_length(iov, iovcnt),
                     iface->config.max_inl_resp + 1, UCT_IB_MAX_MESSAGE_SIZE,
                     "get_zcopy");

    status = uct_rc_mlx5_ep_zcopy_post(ep, MLX5_OPCODE_RDMA_READ, iov, iovcnt,
                                       0, NULL, 0, remote_addr, rkey,
                                       MLX5_WQE_CTRL_CQ_UPDATE, comp);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, &ep->super.super, GET, ZCOPY,
                                 uct_iov_total_length(iov, iovcnt));
    return status;
}

ucs_status_t uct_rc_mlx5_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                     const void *payload, unsigned length)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);

    UCT_RC_MLX5_CHECK_AM_SHORT(id, length, 0);

    UCT_RC_CHECK_RES(iface, &ep->super);
    UCT_RC_CHECK_FC(iface, &ep->super, id);

    uct_rc_mlx5_txqp_inline_post(iface, IBV_QPT_RC,
                                 &ep->super.txqp, &ep->tx.wq,
                                 MLX5_OPCODE_SEND,
                                 payload, length,
                                 id, hdr, 0,
                                 0, 0,
                                 NULL, 0);
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, SHORT, sizeof(hdr) + length);
    UCT_RC_UPDATE_FC(iface, &ep->super, id);
    return UCS_OK;
}

ssize_t uct_rc_mlx5_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                                uct_pack_callback_t pack_cb, void *arg,
                                unsigned flags)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_iface_send_desc_t *desc;
    size_t length;

    UCT_CHECK_AM_ID(id);
    UCT_RC_CHECK_RES(iface, &ep->super);
    UCT_RC_CHECK_FC(iface, &ep->super, id);
    UCT_RC_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.mp, desc,
                                      id, pack_cb, arg, &length);

    uct_rc_mlx5_txqp_bcopy_post(iface, &ep->super.txqp, &ep->tx.wq,
                                MLX5_OPCODE_SEND|UCT_RC_MLX5_OPCODE_FLAG_RAW,
                                sizeof(uct_rc_hdr_t) + length, 0, NULL, 0, 0, 0,
                                0, desc);
    UCT_TL_EP_STAT_OP(&ep->super.super, AM, BCOPY, length);
    UCT_RC_UPDATE_FC(iface, &ep->super, id);
    return length;
}

ucs_status_t uct_rc_mlx5_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                     unsigned header_length, const uct_iov_t *iov,
                                     size_t iovcnt, uct_completion_t *comp)
{
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    ucs_status_t status;

    UCT_CHECK_IOV_SIZE(iovcnt, UCT_IB_MLX5_AM_ZCOPY_MAX_IOV,
                       "uct_rc_mlx5_ep_am_zcopy");
    UCT_RC_MLX5_CHECK_AM_ZCOPY(id, header_length, uct_iov_total_length(iov, iovcnt),
                               iface->super.config.seg_size, 0);
    UCT_RC_CHECK_FC(iface, &ep->super, id);

    status = uct_rc_mlx5_ep_zcopy_post(ep, MLX5_OPCODE_SEND, iov, iovcnt,
                                       id, header, header_length, 0, 0, 0, comp);
    if (ucs_likely(status >= 0)) {
        UCT_TL_EP_STAT_OP(&ep->super.super, AM, ZCOPY,
                          header_length + uct_iov_total_length(iov, iovcnt));
        UCT_RC_UPDATE_FC(iface, &ep->super, id);
    }
    return status;
}

ucs_status_t uct_rc_mlx5_ep_atomic_add64(uct_ep_h tl_ep, uint64_t add,
                                         uint64_t remote_addr, uct_rkey_t rkey)
{
    return uct_rc_mlx5_ep_atomic_add(tl_ep, MLX5_OPCODE_ATOMIC_FA, sizeof(uint64_t),
                                     htobe64(add), remote_addr, rkey);
}

ucs_status_t uct_rc_mlx5_ep_atomic_fadd64(uct_ep_h tl_ep, uint64_t add,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uint64_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_FA, result, 0, sizeof(uint64_t),
                                 remote_addr, rkey, 0, 0, htobe64(add), comp);
}

ucs_status_t uct_rc_mlx5_ep_atomic_swap64(uct_ep_h tl_ep, uint64_t swap,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uint64_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_MASKED_CS, result, 1,
                                 sizeof(uint64_t), remote_addr, rkey, 0, 0,
                                 htobe64(swap), comp);
}

ucs_status_t uct_rc_mlx5_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare, uint64_t swap,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint64_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_CS, result, 0, sizeof(uint64_t),
                                 remote_addr, rkey, 0, htobe64(compare), htobe64(swap),
                                 comp);
}

ucs_status_t uct_rc_mlx5_ep_atomic_add32(uct_ep_h tl_ep, uint32_t add,
                                         uint64_t remote_addr, uct_rkey_t rkey)
{
    return uct_rc_mlx5_ep_atomic_add(tl_ep, MLX5_OPCODE_ATOMIC_MASKED_FA,
                                     sizeof(uint32_t), htonl(add), remote_addr,
                                     rkey);
}

ucs_status_t uct_rc_mlx5_ep_atomic_fadd32(uct_ep_h tl_ep, uint32_t add,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uint32_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_MASKED_FA, result, 1,
                                 sizeof(uint32_t), remote_addr, rkey, 0, 0,
                                 htonl(add), comp);
}

ucs_status_t uct_rc_mlx5_ep_atomic_swap32(uct_ep_h tl_ep, uint32_t swap,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uint32_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_MASKED_CS, result, 1,
                                 sizeof(uint32_t), remote_addr, rkey, 0, 0,
                                 htonl(swap), comp);
}

ucs_status_t uct_rc_mlx5_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare, uint32_t swap,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint32_t *result, uct_completion_t *comp)
{
    return uct_rc_mlx5_ep_atomic(ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t),
                                 MLX5_OPCODE_ATOMIC_MASKED_CS, result, 1,
                                 sizeof(uint32_t), remote_addr, rkey, UCS_MASK(32),
                                 htonl(compare), htonl(swap), comp);
}

ucs_status_t uct_rc_mlx5_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                  uct_completion_t *comp)
{
    uct_rc_mlx5_ep_t *ep = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);
    uct_rc_mlx5_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_mlx5_iface_t);
    ucs_status_t status;
    uint16_t sn;

    status = uct_rc_ep_flush(&ep->super, ep->tx.wq.bb_max);
    if (status != UCS_INPROGRESS) {
        return status;
    }

    if (uct_rc_txqp_unsignaled(&ep->super.txqp) != 0) {
        sn = ep->tx.wq.sw_pi;
        UCT_RC_CHECK_RES(&iface->super, &ep->super);
        uct_rc_mlx5_txqp_inline_post(&iface->super, IBV_QPT_RC,
                                     &ep->super.txqp, &ep->tx.wq,
                                     MLX5_OPCODE_NOP, NULL, 0,
                                     0, 0, 0,
                                     0, 0,
                                     NULL, 0);
    } else {
        sn = ep->tx.wq.sig_pi;
    }

    uct_rc_txqp_add_send_comp(&iface->super, &ep->super.txqp, comp, sn);
    UCT_TL_EP_STAT_FLUSH_WAIT(&ep->super.super);
    return UCS_INPROGRESS;
}

ucs_status_t uct_rc_mlx5_ep_fc_ctrl(uct_ep_t *tl_ep, unsigned op,
                                    uct_rc_fc_request_t *req)
{
    uct_rc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_rc_iface_t);
    uct_rc_mlx5_ep_t *ep  = ucs_derived_of(tl_ep, uct_rc_mlx5_ep_t);

    /* In RC only PURE grant is sent as a separate message. Other FC
     * messages are bundled with AM. */
    ucs_assert(op == UCT_RC_EP_FC_PURE_GRANT);

    UCT_RC_CHECK_RES(iface, &ep->super);
    uct_rc_mlx5_txqp_inline_post(iface, IBV_QPT_RC,
                                 &ep->super.txqp, &ep->tx.wq,
                                 MLX5_OPCODE_SEND|UCT_RC_MLX5_OPCODE_FLAG_RAW,
                                 NULL, 0,
                                 UCT_RC_EP_FC_PURE_GRANT, 0, 0,
                                 0, 0,
                                 NULL, 0);
    return UCS_OK;
}

UCS_CLASS_INIT_FUNC(uct_rc_mlx5_ep_t, uct_iface_h tl_iface)
{
    uct_rc_mlx5_iface_t *iface = ucs_derived_of(tl_iface, uct_rc_mlx5_iface_t);
    ucs_status_t status;

    UCS_CLASS_CALL_SUPER_INIT(uct_rc_ep_t, &iface->super);

    status = uct_ib_mlx5_txwq_init(iface->super.super.super.worker, &self->tx.wq,
                                   self->super.txqp.qp);
    if (status != UCS_OK) {
        ucs_error("Failed to get mlx5 QP information");
        return status;
    }

    self->qp_num       = self->super.txqp.qp->qp_num;
    self->tx.wq.bb_max = ucs_min(self->tx.wq.bb_max, iface->tx.bb_max);
    uct_rc_txqp_available_set(&self->super.txqp, self->tx.wq.bb_max);

    uct_worker_progress_add_safe(iface->super.super.super.worker,
                                 uct_rc_mlx5_iface_progress, iface,
                                 &iface->super.super.super.prog);
    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_rc_mlx5_ep_t)
{
    uct_rc_mlx5_iface_t *iface = ucs_derived_of(self->super.super.super.iface,
                                                uct_rc_mlx5_iface_t);

    uct_worker_progress_remove(iface->super.super.super.worker,
                               &iface->super.super.super.prog);
    uct_ib_mlx5_txwq_cleanup(&self->tx.wq);

    /* Modify QP to error to make HW generate CQEs for all in-progress SRQ
     * receives from the QP, so we clean them all before ibv_modify_qp() can
     * see them.
     */
    (void)uct_rc_modify_qp(&self->super.txqp, IBV_QPS_ERR);
    uct_rc_mlx5_iface_commom_clean_srq(&iface->mlx5_common, &iface->super,
                                       self->qp_num);

    /* Synchronize CQ index with the driver, since it would remove pending
     * completions for this QP (both send and receive) during ibv_destroy_qp().
     */
    uct_rc_mlx5_iface_common_update_cqs_ci(&iface->mlx5_common, &iface->super.super);
    (void)uct_rc_modify_qp(&self->super.txqp, IBV_QPS_RESET);
    uct_rc_mlx5_iface_common_sync_cqs_ci(&iface->mlx5_common, &iface->super.super);

    uct_ib_mlx5_srq_cleanup(&iface->mlx5_common.rx.srq, iface->super.rx.srq.srq);
}

UCS_CLASS_DEFINE(uct_rc_mlx5_ep_t, uct_rc_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_rc_mlx5_ep_t, uct_ep_t, uct_iface_h);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_rc_mlx5_ep_t, uct_ep_t);
