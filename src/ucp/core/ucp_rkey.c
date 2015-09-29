/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "ucp_mm.h"

#include <inttypes.h>


ucs_status_t ucp_rkey_pack(ucp_context_h context, ucp_mem_h memh,
                           void **rkey_buffer_p, size_t *size_p)
{
    unsigned pd_index, uct_memh_index;
    void *rkey_buffer, *p;
    size_t size, pd_size;

    ucs_trace("packing rkeys for buffer %p memh %p pd_map 0x%"PRIx64,
              memh->address, memh, memh->pd_map);

    size = sizeof(uint64_t);
    for (pd_index = 0; pd_index < context->num_pds; ++pd_index) {
        size += sizeof(uint8_t);
        pd_size = context->pd_attrs[pd_index].rkey_packed_size;
        ucs_assert_always(pd_size < UINT8_MAX);
        size += pd_size;
    }

    rkey_buffer = ucs_malloc(size, "ucp_rkey_buffer");
    if (rkey_buffer == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    p = rkey_buffer;

    /* Write the PD map */
    *(uint64_t*)p = memh->pd_map;
    p += sizeof(uint64_t);

    /* Write both size and rkey_buffer for each UCT rkey */
    uct_memh_index = 0;
    for (pd_index = 0; pd_index < context->num_pds; ++pd_index) {
        if (!(memh->pd_map & UCS_BIT(pd_index))) {
            continue;
        }

        pd_size = context->pd_attrs[pd_index].rkey_packed_size;
        *((uint8_t*)p++) = pd_size;
        uct_pd_mkey_pack(context->pds[pd_index], memh->uct[uct_memh_index], p);
        ++uct_memh_index;
        p += pd_size;
    }

    *rkey_buffer_p = rkey_buffer;
    *size_p        = size;
    return UCS_OK;
}

void ucp_rkey_buffer_release(void *rkey_buffer)
{
    ucs_free(rkey_buffer);
}

ucs_status_t ucp_ep_rkey_unpack(ucp_ep_h ep, void *rkey_buffer, ucp_rkey_h *rkey_p)
{
    unsigned remote_pd_index, remote_pd_gap;
    unsigned rkey_index;
    unsigned pd_count;
    ucs_status_t status;
    ucp_rkey_h rkey;
    uint8_t pd_size;
    uint64_t pd_map;
    void *p;

    /* Count the number of remote PDs in the rkey buffer */
    p = rkey_buffer;

    /* Read remote PD map */
    pd_map   = *(uint64_t*)p;
    pd_count = ucs_count_one_bits(pd_map);
    p       += sizeof(uint64_t);

    /* Allocate rkey handle which holds UCT rkeys for all remote PDs.
     * We keep all of them to handle a future transport switch.
     */
    rkey = ucs_malloc(sizeof(*rkey) + (sizeof(rkey->uct[0]) * pd_count), "ucp_rkey");
    if (rkey == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    rkey->pd_map    = 0;
    remote_pd_index = 0; /* Index of remote PD */
    rkey_index      = 0; /* Index of the rkey in the array */

    /* Unpack rkey of each UCT PD */
    ucs_trace("unpacking rkey with pd_map 0x%"PRIx64, pd_map);
    while (pd_map > 0) {
        pd_size = *((uint8_t*)p++);

        /* Use bit operations to iterate through the indices of the remote PDs
         * as provided in the pd_map. pd_map always holds a bitmap of PD indices
         * that remain to be used. Every time we find the "gap" until the next
         * valid PD index using ffs operation. If some rkeys cannot be unpacked,
         * we remove them from the local map.
         */
        remote_pd_gap    = ucs_ffs64(pd_map); /* Find the offset for next PD index */
        remote_pd_index += remote_pd_gap;      /* Calculate next index of remote PD*/
        pd_map >>= remote_pd_gap;                   /* Remove the gap from the map */
        ucs_assert(pd_map & 1);

        /* Unpack only reachable rkeys */
        if (ep->dst_pd_index == remote_pd_index) {
            ucs_assert(rkey_index < pd_count);
            status = uct_rkey_unpack(p, &rkey->uct[rkey_index]);
            if (status != UCS_OK) {
                ucs_error("Failed to unpack remote key from remote pd[%d]: %s",
                          remote_pd_index, ucs_status_string(status));
                goto err_destroy;
            }

            ucs_trace("rkey[%d] for remote pd %d is 0x%lx", rkey_index,
                      remote_pd_index, rkey->uct[rkey_index].rkey);
            rkey->pd_map |= UCS_BIT(remote_pd_index);
            ++rkey_index;
        }

        ++remote_pd_index;
        pd_map >>= 1;
        p += pd_size;
    }

    if (rkey->pd_map == 0) {
        ucs_debug("The unpacked rkey from the destination is unreachable");
        status = UCS_ERR_UNREACHABLE;
        goto err_destroy;
    }

    *rkey_p = rkey;
    return UCS_OK;

err_destroy:
    ucp_rkey_destroy(rkey);
err:
    return status;
}

void ucp_rkey_destroy(ucp_rkey_h rkey)
{
    unsigned num_rkeys = ucs_count_one_bits(rkey->pd_map);
    unsigned i;

    for (i = 0; i < num_rkeys; ++i) {
        uct_rkey_release(&rkey->uct[i]);
    }
    ucs_free(rkey);
}
