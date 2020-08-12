/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "proto_multi.h"
#include "proto_common.h"

#include <ucs/debug/assert.h>
#include <ucs/debug/log.h>


ucs_status_t ucp_proto_multi_init(const ucp_proto_multi_init_params_t *params)
{
    ucp_proto_multi_priv_t *mpriv = params->super.super.priv;
    ucp_lane_index_t lanes[UCP_PROTO_MAX_LANES];
    double lanes_bandwidth[UCP_PROTO_MAX_LANES];
    ucp_proto_common_perf_params_t perf_params;
    const uct_iface_attr_t *iface_attr;
    ucp_proto_multi_lane_priv_t *lpriv;
    ucp_md_index_t md_index;
    double total_bandwidth;
    ucp_lane_index_t i;

    ucs_assert(params->max_lanes >= 1);
    ucs_assert(params->max_lanes <= UCP_PROTO_MAX_LANES);

    mpriv->reg_md_map = 0;

    /* Find first lane */
    mpriv->num_lanes = ucp_proto_common_find_lanes(&params->super,
                                                   params->first.lane_type,
                                                   params->first.tl_cap_flags,
                                                   lanes, 1, 0);
    if (mpriv->num_lanes == 0) {
        ucs_trace("no lanes for %s", params->super.super.proto_name);
        return UCS_ERR_UNSUPPORTED;
    }

    /* Find rest of the lanes */
    mpriv->num_lanes += ucp_proto_common_find_lanes(&params->super,
                                                    params->middle.lane_type,
                                                    params->middle.tl_cap_flags,
                                                    lanes + 1,
                                                    params->max_lanes - 1,
                                                    UCS_BIT(lanes[0]));

    /* Fill the size of private data */
    *params->super.super.priv_size =
            sizeof(ucp_proto_multi_priv_t) +
            (mpriv->num_lanes * ucs_field_sizeof(ucp_proto_multi_priv_t, lanes[0]));

    /* Initialize parameters for calculating performance */
    perf_params.lane_map = 0;
    perf_params.lane0    = lanes[0];
    perf_params.is_multi = 1;

    /* Collect information from all lanes */
    total_bandwidth      = 0;
    for (i = 0; i < mpriv->num_lanes; ++i) {
        lpriv                 = &mpriv->lanes[i];

        perf_params.lane_map |= UCS_BIT(lanes[i]);
        iface_attr            = ucp_proto_common_get_iface_attr(&params->super.super,
                                                                lanes[i]);
        lanes_bandwidth[i]    = ucp_proto_common_iface_bandwidth(&params->super,
                                                                 iface_attr);
        total_bandwidth      += lanes_bandwidth[i];

        lpriv->lane           = lanes[i];
        lpriv->max_frag       = ucp_proto_get_iface_attr_field(iface_attr,
                                               params->super.fragsz_offset);
        md_index              = ucp_proto_common_get_md_index(&params->super.super,
                                                              lanes[i]);
        mpriv->reg_md_map    |= UCS_BIT(md_index);
    }

    /* Set up the relative weights */
    for (i = 0; i < mpriv->num_lanes; ++i) {
        mpriv->lanes[i].weight = lanes_bandwidth[i] / total_bandwidth;
    }

    ucp_proto_common_calc_perf(&params->super, &perf_params);

    return UCS_OK;
}

void ucp_proto_multi_config_str(const void *priv, ucs_string_buffer_t *strb)
{
    const ucp_proto_multi_priv_t *mpriv = priv;
    const ucp_proto_multi_lane_priv_t *lpriv;
    ucp_lane_index_t i;
    double weight;

    ucs_string_buffer_init(strb);

    for (i = 0; i < mpriv->num_lanes; ++i) {
        lpriv  = &mpriv->lanes[i];
        weight = 100.0 * lpriv->weight;
        if (i > 0) {
            ucs_string_buffer_appendf(strb, ", ");
        }
        ucs_string_buffer_appendf(strb, "%.0f%%:lane[%d]", weight,
                                  lpriv->lane);
    }
}
