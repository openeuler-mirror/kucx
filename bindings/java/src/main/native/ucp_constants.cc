/*
 * Copyright (C) Mellanox Technologies Ltd. 2019. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "org_openucx_jucx_ucp_UcpConstants.h"
#include "jucx_common_def.h"

#include <ucp/api/ucp.h>


/**
 * @brief Routine to set UCX constants in java
 *
 */
JNIEXPORT void JNICALL
Java_org_openucx_jucx_ucp_UcpConstants_loadConstants(JNIEnv *env, jclass cls)
{
    // UCP context parameters
    JUCX_DEFINE_LONG_CONSTANT(UCP_PARAM_FIELD_FEATURES);
    JUCX_DEFINE_LONG_CONSTANT(UCP_PARAM_FIELD_FEATURES);
    JUCX_DEFINE_LONG_CONSTANT(UCP_PARAM_FIELD_TAG_SENDER_MASK);
    JUCX_DEFINE_LONG_CONSTANT(UCP_PARAM_FIELD_MT_WORKERS_SHARED);
    JUCX_DEFINE_LONG_CONSTANT(UCP_PARAM_FIELD_ESTIMATED_NUM_EPS);

    // UCP configuration features
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_TAG);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_RMA);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_AMO32);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_AMO64);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_WAKEUP);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_STREAM);
    JUCX_DEFINE_LONG_CONSTANT(UCP_FEATURE_AM);

    // UCP worker parameters
    JUCX_DEFINE_LONG_CONSTANT(UCP_WORKER_PARAM_FIELD_THREAD_MODE);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WORKER_PARAM_FIELD_CPU_MASK);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WORKER_PARAM_FIELD_EVENTS);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WORKER_PARAM_FIELD_USER_DATA);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WORKER_PARAM_FIELD_EVENT_FD);

    // UCP worker wakeup events
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_RMA);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_AMO);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_TAG_SEND);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_TAG_RECV);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_TX);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_RX);
    JUCX_DEFINE_LONG_CONSTANT(UCP_WAKEUP_EDGE);

    // UCP listener parameters field mask
    JUCX_DEFINE_LONG_CONSTANT(UCP_LISTENER_PARAM_FIELD_SOCK_ADDR);
    JUCX_DEFINE_LONG_CONSTANT(UCP_LISTENER_PARAM_FIELD_ACCEPT_HANDLER);
    JUCX_DEFINE_LONG_CONSTANT(UCP_LISTENER_PARAM_FIELD_CONN_HANDLER);

    // UCP endpoint parameters field mask
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_REMOTE_ADDRESS);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_ERR_HANDLER);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_USER_DATA);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_SOCK_ADDR);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_FLAGS);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAM_FIELD_CONN_REQUEST);

    // UCP error handling mode
    JUCX_DEFINE_INT_CONSTANT(UCP_ERR_HANDLING_MODE_PEER);

    // UCP endpoint close non blocking mode.
    JUCX_DEFINE_INT_CONSTANT(UCP_EP_CLOSE_FLAG_FORCE);

    // The enumeration list describes the endpoint's parameters flags
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAMS_FLAGS_CLIENT_SERVER);
    JUCX_DEFINE_LONG_CONSTANT(UCP_EP_PARAMS_FLAGS_NO_LOOPBACK);

    // UCP memory mapping parameters field mask
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PARAM_FIELD_ADDRESS);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PARAM_FIELD_LENGTH);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PARAM_FIELD_FLAGS);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PARAM_FIELD_PROT);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PARAM_FIELD_MEMORY_TYPE);

    // The enumeration list describes the memory mapping flags
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_NONBLOCK);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_ALLOCATE);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_FIXED);

    // The enumeration list describes the memory mapping protections
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PROT_LOCAL_READ);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PROT_LOCAL_WRITE);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PROT_REMOTE_READ);
    JUCX_DEFINE_LONG_CONSTANT(UCP_MEM_MAP_PROT_REMOTE_WRITE);

    // The enumeration defines behavior of @ref ucp_stream_recv_nb function
    JUCX_DEFINE_LONG_CONSTANT(UCP_STREAM_RECV_FLAG_WAITALL);

    // The enumeration allows specifying which fields in @ref ucp_am_recv_param_t
    // are present and receive operation flags are used.
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_RECV_ATTR_FLAG_DATA);
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_RECV_ATTR_FLAG_RNDV);

    // Flags dictate the behavior of @ref ucp_am_send_nbx routine.
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_SEND_FLAG_REPLY);
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_SEND_FLAG_EAGER);
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_SEND_FLAG_RNDV);

    // Flags that indicate how to handle UCP Active Messages.
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_FLAG_WHOLE_MSG);
    JUCX_DEFINE_LONG_CONSTANT(UCP_AM_FLAG_PERSISTENT_DATA);
}
