/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 */

#ifndef UCP_FAILOVER_H_
#define UCP_FAILOVER_H_

#include <uct/api/uct_def.h>
#include "ucp_types.h"

typedef enum {
    UCP_FO_FLAG_UNKNOWN          = UCS_BIT(0),
    UCP_FO_FLAG_INIT             = UCS_BIT(1),      // init fo ctx
    UCP_FO_FLAG_SELECTED         = UCS_BIT(2),      // ucp has selected new lane
    UCP_FO_FLAG_SENT             = UCS_BIT(3),      // meta info has been sent
    UCP_FO_FLAG_REPLY            = UCS_BIT(4),      // meta info has replyed
    UCP_FO_FLAG_RESEND           = UCS_BIT(5),      // resended
    UCP_FO_FLAG_REPLY_META       = UCS_BIT(6),      // special flag for reply meta
    UCP_FO_FLAG_RESOLVED_EP_ID   = UCS_BIT(7),      // ucp wireup ep id resolved
    UCP_FO_FLAG_PRE_HANDLED      = UCS_BIT(8),      // pre-handle
    UCP_FO_FLAG_CHANGE_TL_MAP    = UCS_BIT(9),      // change tl map
    UCP_FO_FLAG_REVISED          = UCS_BIT(10),     // multi-point faults need to revise dest_lane
} ucp_fo_state_t;

typedef enum {
    LANE_TYPE_AM            = UCS_BIT(0),
    LANE_TYPE_KEY_TAG       = UCS_BIT(1),
    LANE_TYPE_AM_BW         = UCS_BIT(2),
    LANE_TYPE_TAG           = UCS_BIT(3),
    LANE_TYPE_WIREUP_MSG    = UCS_BIT(4),
    LANE_TYPE_RMA_BW        = UCS_BIT(5),
    LANE_TYPE_REVISE        = UCS_BIT(7)        // revise lane for multi-point fault
} lane_type_t;

typedef enum {
    /* only one ep fault, iface may be ok, this happens that peer-end is fault */
    LANE_FAULT_TYPE_EP          = UCS_BIT(0),
    /* iface fault, means all ep in iface are fault */
    LANE_FAULT_TYPE_IFACE       = UCS_BIT(1),
} lane_fault_type_t;

typedef struct failover_ctx {
    lane_type_t lane_type;
    lane_fault_type_t lane_fault_type;
    ucp_fo_state_t state;
    uint64_t guid;
    ucp_lane_index_t origin_lane;
    ucp_lane_index_t remote_origin_lane;
    ucp_lane_index_t new_lane;
    ucp_lane_index_t remote_new_lane;
    uint64_t peer_private_data;
    uct_rkey_ctx_t rkey_ctx;     // for get rkey
    ucs_time_t cycle_time;
} failover_ctx_t;

typedef struct ucp_failover_ctx {
    uint8_t failover_num;
    failover_ctx_t *failover_array[UCP_MAX_LANES];  // failover ctx being processed
    uct_worker_cb_id_t failover_id;     // for progress
    uct_worker_cb_id_t wireup_timeout_check_prog_id;        // for aux wireup
} ucp_failover_ctx_t;

ucs_status_t ucp_worker_iface_failover_error_handler(void *arg, uct_iface_h uct_iface);

void ucp_failover_lane_connect_fault_handler(ucp_ep_h ucp_ep, ucp_lane_index_t lane);

ucs_status_t ucp_worker_ep_failover_error_handler(void *arg, uct_ep_h uct_ep);

#endif