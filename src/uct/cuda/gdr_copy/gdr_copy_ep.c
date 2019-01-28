/**
 * Copyright (C) Mellanox Technologies Ltd. 2017-2019.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "gdr_copy_ep.h"
#include "gdr_copy_md.h"
#include "gdr_copy_iface.h"

#include <uct/base/uct_log.h>
#include <ucs/debug/memtrack.h>
#include <ucs/sys/math.h>
#include <ucs/type/class.h>


static UCS_CLASS_INIT_FUNC(uct_gdr_copy_ep_t, const uct_ep_params_t *params)
{
    uct_gdr_copy_iface_t *iface = ucs_derived_of(params->iface,
                                                 uct_gdr_copy_iface_t);

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_gdr_copy_ep_t)
{
}

UCS_CLASS_DEFINE(uct_gdr_copy_ep_t, uct_base_ep_t)
UCS_CLASS_DEFINE_NEW_FUNC(uct_gdr_copy_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gdr_copy_ep_t, uct_ep_t);

ucs_status_t uct_gdr_copy_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                       unsigned length, uint64_t remote_addr,
                                       uct_rkey_t rkey)
{
    uct_gdr_copy_key_t *gdr_copy_key = (uct_gdr_copy_key_t *) rkey;
    size_t bar_offset;
    int ret;

    if (ucs_likely(length)) {
        bar_offset = remote_addr - gdr_copy_key->vaddr;
        ret = gdr_copy_to_bar(gdr_copy_key->bar_ptr + bar_offset, buffer, length);
        if (ret) {
            ucs_error("gdr_copy_to_bar failed. ret:%d", ret);
            return UCS_ERR_IO_ERROR;
        }
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, SHORT, length);
    ucs_trace_data("PUT_SHORT size %d from %p to %p",
                   length, buffer, (void *)remote_addr);
    return UCS_OK;
}

ucs_status_t uct_gdr_copy_ep_get_short(uct_ep_h tl_ep, void *buffer,
                                       unsigned length, uint64_t remote_addr,
                                       uct_rkey_t rkey)
{
    uct_gdr_copy_key_t *gdr_copy_key = (uct_gdr_copy_key_t *) rkey;
    size_t bar_offset;
    int ret;

    if (ucs_likely(length)) {
        bar_offset = remote_addr - gdr_copy_key->vaddr;
        ret = gdr_copy_from_bar(buffer, gdr_copy_key->bar_ptr + bar_offset, length);
        if (ret) {
            ucs_error("gdr_copy_from_bar failed. ret:%d", ret);
            return UCS_ERR_IO_ERROR;
        }
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, SHORT, length);
    ucs_trace_data("GET_SHORT size %d from %p to %p",
                   length, (void *)remote_addr, buffer);
    return UCS_OK;
}
