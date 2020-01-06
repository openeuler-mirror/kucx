/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_CM_H_
#define UCT_CM_H_

#include <uct/api/uct_def.h>
#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <ucs/type/class.h>


UCS_CLASS_DECLARE(uct_listener_t, uct_cm_h);

/**
 * "Base" structure which defines CM configuration options.
 * Specific CMs extend this structure.
 */
struct uct_cm_config {
    /* C standard prohibits empty structures */
    char  __dummy;
};

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


/**
 * Connection manager base endpoint
 */
typedef struct uct_cm_base_ep {
    uct_base_ep_t                      super;

    /* User data associated with the endpoint */
    void                               *user_data;

    /* Callback to handle the disconnection of the remote peer */
    uct_ep_disconnect_cb_t             disconnect_cb;

    /* Callback to fill the user's private data */
    uct_sockaddr_priv_pack_callback_t  priv_pack_cb;

    union {
        struct {
            /* On the client side - callback to process an incoming
             * connection response from the server */
            uct_ep_client_connect_cb_t connect_cb;
        } client;
        struct {
            /* On the server side - callback to process an incoming connection
             * establishment acknowledgment from the client */
            uct_ep_server_connect_cb_t connect_cb;
        } server;
    };
} uct_cm_base_ep_t;


UCS_CLASS_DECLARE(uct_cm_base_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_NEW_FUNC(uct_cm_base_ep_t, uct_base_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_cm_base_ep_t, uct_base_ep_t);


extern ucs_config_field_t uct_cm_config_table[];

UCS_CLASS_DECLARE(uct_cm_t, uct_cm_ops_t*, uct_iface_ops_t*, uct_worker_h,
                  uct_component_h);

ucs_status_t uct_cm_check_ep_params(const uct_ep_params_t *params);

#endif /* UCT_CM_H_ */
