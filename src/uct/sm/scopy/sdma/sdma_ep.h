/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */
#ifndef UCT_SDMA_EP_H
#define UCT_SDMA_EP_H

#include <sys/ipc.h>
#include <sys/shm.h>
#include "sdma_iface.h"

#define SHMEM_SIZE 65535
#define PERMIS_FLAG 0666
#define SHMEM_KEY_GET(a, b) ((a)*100 + (b))
#define SDMA_SHMEM_ERRCODE (-1)

typedef struct uct_sdma_ep {
    uct_base_ep_t super;
    int remote_pasid;
    int remote_devid;
    int ep_pasid;
    int local_ifaceid;
    int remote_ifaceid;
    void *chn_ctx;
    ucs_spinlock_t lock;
    sdma_shmem_msg_t *remote_shmem_msg;
    uct_sdma_req_queue_t *req_q;
    ucs_arbiter_group_t arb_group;
} uct_sdma_ep_t;

/**
 * Context for memcpy pack callback.
 */
typedef struct {
    const void *src;
    size_t length;
} pack_context_t;

UCS_CLASS_DECLARE_NEW_FUNC(uct_sdma_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_sdma_ep_t, uct_ep_t);

ucs_status_t uct_sdma_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t header, const void *payload, unsigned length);

ssize_t uct_sdma_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id, uct_pack_callback_t pack_cb, void *arg, unsigned flags);

ucs_status_t uct_sdma_ep_put_short(uct_ep_h tl_ep, const void *buffer, unsigned length, uint64_t remote_addr,
    uct_rkey_t rkey);

ssize_t uct_sdma_ep_put_bcopy(uct_ep_h ep, uct_pack_callback_t pack_cb, void *arg, uint64_t remote_addr,
    uct_rkey_t rkey);

ucs_status_t uct_sdma_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iov_cnt, uint64_t remote_addr,
    uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_sdma_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iov_cnt, uint64_t remote_addr,
    uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_sdma_ep_get_bcopy(uct_ep_h tl_ep, uct_unpack_callback_t unpack_cb, void *arg, size_t length,
    uint64_t remote_addr, uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_creat_shmem(int ftok_id, sdma_shmem_msg_t *shmem_msg);

ucs_status_t uct_shmem_del(sdma_shmem_msg_t *shmem_msg);

ucs_status_t uct_sdma_ep_flush(uct_ep_h tl_ep, unsigned flags, uct_completion_t *comp);
#endif
