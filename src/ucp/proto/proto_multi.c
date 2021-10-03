/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "proto_common.inl"
#include "proto_multi.inl"

#include <ucs/debug/assert.h>
#include <ucs/debug/log.h>


ucs_status_t ucp_proto_multi_init(const ucp_proto_multi_init_params_t *params,
                                  ucp_proto_multi_priv_t *mpriv,
                                  size_t *priv_size_p)
{
    ucp_context_h context         = params->super.super.worker->context;
    const double max_bw_ratio     = context->config.ext.multi_lane_max_ratio;
    ucp_proto_common_tl_perf_t lanes_perf[UCP_PROTO_MAX_LANES];
    ucp_proto_common_tl_perf_t *lane_perf, perf;
    ucp_lane_index_t lanes[UCP_PROTO_MAX_LANES];
    double max_bandwidth, max_frag_ratio;
    ucp_lane_index_t i, lane, num_lanes;
    ucp_proto_multi_lane_priv_t *lpriv;
    size_t max_frag, min_length;
    ucp_lane_map_t lane_map;
    ucp_md_map_t reg_md_map;
    uint32_t weight_sum;
    ucs_status_t status;

    ucs_assert(params->max_lanes >= 1);
    ucs_assert(params->max_lanes <= UCP_PROTO_MAX_LANES);

    /* Find first lane */
    num_lanes = ucp_proto_common_find_lanes(&params->super,
                                            params->first.lane_type,
                                            params->first.tl_cap_flags, 1, 0,
                                            lanes);
    if (num_lanes == 0) {
        ucs_trace("no lanes for %s", params->super.super.proto_name);
        return UCS_ERR_NO_ELEM;
    }

    /* Find rest of the lanes */
    num_lanes += ucp_proto_common_find_lanes(&params->super,
                                             params->middle.lane_type,
                                             params->middle.tl_cap_flags,
                                             params->max_lanes - 1,
                                             UCS_BIT(lanes[0]), lanes + 1);

    /* Get bandwidth of all lanes and max_bandwidth */
    max_bandwidth = 0;
    for (i = 0; i < num_lanes; ++i) {
        lane      = lanes[i];
        lane_perf = &lanes_perf[lane];

        status = ucp_proto_common_get_lane_perf(&params->super, lane,
                                                lane_perf);
        if (status != UCS_OK) {
            return status;
        }

        /* Calculate maximal bandwidth of all lanes, to skip slow lanes */
        max_bandwidth = ucs_max(max_bandwidth, lane_perf->bandwidth);
    }

    /* Select the lanes to use, and calculate their aggregate performance */
    perf.bandwidth   = 0;
    perf.overhead    = 0;
    perf.latency     = 0;
    perf.sys_latency = 0;
    lane_map         = 0;
    max_frag_ratio   = 0;
    for (i = 0; i < num_lanes; ++i) {
        lane      = lanes[i];
        lane_perf = &lanes_perf[lane];
        if ((lane_perf->bandwidth * max_bw_ratio) < max_bandwidth) {
            /* Bandwidth on this lane is too low compared to the fastest
               available lane, so it's not worth using it */
            continue;
        }

        ucs_trace("lane[%d]" UCP_PROTO_TIME_FMT(overhead)
                  UCP_PROTO_TIME_FMT(latency),
                  lane, UCP_PROTO_TIME_ARG(lane_perf->overhead),
                  UCP_PROTO_TIME_ARG(lane_perf->latency));

        /* Calculate maximal bandwidth-to-fragment-size ratio, which is used to
           adjust fragment sizes so they are proportional to bandwidth ratio and
           also do not exceed maximal supported size */
        max_frag_ratio = ucs_max(max_frag_ratio,
                                 lane_perf->bandwidth / lane_perf->max_frag);

        /* Update aggregated performance metric */
        perf.bandwidth  += lane_perf->bandwidth;
        perf.overhead   += lane_perf->overhead;
        perf.latency     = ucs_max(perf.latency, lane_perf->latency);
        perf.sys_latency = ucs_max(perf.sys_latency, lane_perf->sys_latency);
        lane_map        |= UCS_BIT(lane);
    }

    /* Initialize multi-lane private data and relative weights */
    reg_md_map          = ucp_proto_common_reg_md_map(&params->super, lane_map);
    mpriv->reg_md_map   = reg_md_map | params->initial_reg_md_map;
    mpriv->lane_map     = lane_map;
    mpriv->num_lanes    = 0;
    mpriv->max_frag_sum = 0;
    perf.max_frag       = SIZE_MAX;
    perf.min_length     = 0;
    weight_sum          = 0;
    ucs_for_each_bit(lane, lane_map) {
        ucs_assert(lane < UCP_MAX_LANES);

        lpriv     = &mpriv->lanes[mpriv->num_lanes++];
        lane_perf = &lanes_perf[lane];

        ucp_proto_common_lane_priv_init(&params->super, mpriv->reg_md_map, lane,
                                        &lpriv->super);

        /* Calculate maximal fragment size according to lane relative bandwidth.
           Due to floating-point accuracy, max_frag may be too large. */
        max_frag = ucs_double_to_sizet(lane_perf->bandwidth / max_frag_ratio,
                                       lane_perf->max_frag);

        /* Make sure fragment is not zero */
        ucs_assert(max_frag > 0);

        lpriv->max_frag = max_frag;
        perf.max_frag   = ucs_min(perf.max_frag, lpriv->max_frag);


        /* Calculate lane weight as a fixed-point fraction */
        lpriv->weight = ucs_proto_multi_calc_weight(lane_perf->bandwidth,
                                                    perf.bandwidth);
        ucs_assert(lpriv->weight > 0);
        ucs_assert(lpriv->weight <= UCP_PROTO_MULTI_WEIGHT_MAX);

        /* Calculate minimal message length according to lane's relative weight:
           When the message length is scaled by this lane's weight, it must not
           be lower than 'lane_perf->min_length'. Proof of the below formula:

            Since we calculated min_length by our formula:
                length >= (lane_perf->min_length << SHIFT) / weight

            Let's mark "(lane_perf->min_length << SHIFT)" as "M" for simplicity:
                length >= M / weight

            Since weight <= mask + 1, then weight - (mask + 1) <= 0, so we get:
                length >= (M + weight - (mask + 1)) / weight)

            Changing order:
                length >= ((M - mask) + (weight - 1)) / weight)

            The righthand expression is actually rounding up the result of
            "M - mask" divided by weight. So if we multiplied the righthand
            expression by weight, it would be >= "M - mask".
            We can multiply both sides by weight and get:
                length * weight >= "righthand expression" * weight >= M - mask
            So:
                length * weight >= M - mask

            Changing order:
                length * weight + mask >= M = lane_perf->min_length << SHIFT

            Shifting right, we get the needed inequality, which means the result
            of ucp_proto_multi_scaled_length() will be always greater or equal
            to min_length:
                (length * weight + mask) >> SHIFT >= lane_perf->min_length
        */
        min_length = (lane_perf->min_length << UCP_PROTO_MULTI_WEIGHT_SHIFT) /
                     lpriv->weight;
        ucs_assert(ucp_proto_multi_scaled_length(lpriv->weight, min_length) >=
                   lane_perf->min_length);
        perf.min_length = ucs_max(perf.min_length, min_length);

        weight_sum          += lpriv->weight;
        mpriv->max_frag_sum += lpriv->max_frag;
        lpriv->weight_sum    = weight_sum;
        lpriv->max_frag_sum  = mpriv->max_frag_sum;
    }

    /* Fill the size of private data according to number of used lanes */
    *priv_size_p = sizeof(ucp_proto_multi_priv_t) +
                   (mpriv->num_lanes * sizeof(*lpriv));

    return ucp_proto_common_init_caps(&params->super, &perf, reg_md_map);
}

void ucp_proto_multi_config_str(size_t min_length, size_t max_length,
                                const void *priv, ucs_string_buffer_t *strb)
{
    const ucp_proto_multi_priv_t *mpriv = priv;
    const ucp_proto_multi_lane_priv_t *lpriv;
    size_t percent, remaining;
    char frag_size_buf[64];
    ucp_lane_index_t i;

    ucs_assert(mpriv->num_lanes <= UCP_MAX_LANES);

    remaining = 100;
    for (i = 0; i < mpriv->num_lanes; ++i) {
        lpriv      = &mpriv->lanes[i];
        percent    = ucs_min(remaining,
                             ucp_proto_multi_scaled_length(lpriv->weight, 100));
        remaining -= percent;

        if (percent != 100) {
            ucs_string_buffer_appendf(strb, "%zu%%*", percent);
        }

        ucp_proto_common_lane_priv_str(&lpriv->super, strb);

        /* Print fragment size if it's small enough. For large fragments we can
           skip the print because it has little effect on performance */
        if (lpriv->max_frag < (64 * UCS_KBYTE)) {
            ucs_memunits_to_str(lpriv->max_frag, frag_size_buf,
                                sizeof(frag_size_buf));
            ucs_string_buffer_appendf(strb, "<=%s", frag_size_buf);
        }

        if ((i + 1) < mpriv->num_lanes) {
            ucs_string_buffer_appendf(strb, "|");
        }
    }
}
