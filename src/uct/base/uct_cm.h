/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_CM_H_
#define UCT_CM_H_

#include <uct/api/uct_def.h>
#include <uct/base/uct_md.h>

UCS_CLASS_DECLARE(uct_listener_t, uct_cm_h);

/**
 * Connection manager component operations
 */
typedef struct uct_cm_ops {
    void         (*close)(uct_cm_h cm);
    ucs_status_t (*cm_query)(uct_cm_h cm, uct_cm_attr_t *cm_attr);
    ucs_status_t (*listener_create)(uct_cm_h cm, const struct sockaddr *saddr,
                                    socklen_t socklen,
                                    const uct_listener_params_t *params,
                                    uct_listener_h *listener_p);
    ucs_status_t (*listener_reject)(uct_listener_h listener,
                                    uct_conn_request_h conn_request);
    ucs_status_t (*listener_query) (uct_listener_h listener,
                                    uct_listener_attr_t *listener_attr);
    void         (*listener_destroy)(uct_listener_h listener);
    ucs_status_t (*ep_create)(const uct_ep_params_t *params, uct_ep_h *ep_p);
} uct_cm_ops_t;


struct uct_cm {
    uct_cm_ops_t     *ops;
    uct_component_h  component;
    uct_base_iface_t iface;
};

UCS_CLASS_DECLARE(uct_cm_t, uct_cm_ops_t*, uct_iface_ops_t*, uct_worker_h,
                  uct_component_h);

#endif /* UCT_CM_H_ */
