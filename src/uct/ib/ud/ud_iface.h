/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
*
* $COPYRIGHT$
* $HEADER$
*/


#ifndef UCT_UD_IFACE_H
#define UCT_UD_IFACE_H

#include <uct/ib/base/ib_iface.h>
#include <ucs/datastruct/sglib_wrapper.h>
#include <ucs/datastruct/ptr_array.h>
#include <ucs/datastruct/sglib.h>

#include "ud_def.h"
#include "ud_ep.h"


#define UCT_UD_MIN_INLINE   48
struct uct_ud_iface_addr {
    uct_iface_addr_t     super;
    uint32_t             qp_num;
    uint32_t             lid;
    /* TODO: add mtu */
};


/* TODO: maybe tx_moderation can be defined at compile-time since tx completions are used only to know how much space is there in tx qp */

typedef struct uct_ud_iface_config {
    uct_ib_iface_config_t    super;
} uct_ud_iface_config_t;

struct uct_ud_iface_peer {
    uct_ud_iface_peer_t   *next;
    uct_ud_iface_addr_t    dest_iface;
    uct_ud_ep_t           *eps[UCT_UD_HASH_SIZE];
    int                    ep_count;
    uint32_t               conn_id_last;
};

static inline int uct_ud_iface_peer_cmp(uct_ud_iface_peer_t *a, uct_ud_iface_peer_t *b) {
    return a->dest_iface.qp_num - b->dest_iface.qp_num ||  
           a->dest_iface.lid - b->dest_iface.lid;
}

static inline int uct_ud_iface_peer_hash(uct_ud_iface_peer_t *a) {
    return a->dest_iface.lid % UCT_UD_HASH_SIZE; 
}

SGLIB_DEFINE_LIST_PROTOTYPES(uct_ud_iface_peer_t, uct_ud_iface_peer_cmp, next)
SGLIB_DEFINE_HASHED_CONTAINER_PROTOTYPES(uct_ud_iface_peer_t, UCT_UD_HASH_SIZE, uct_ud_iface_peer_hash)

struct uct_ud_iface {
    uct_ib_iface_t           super;
    struct ibv_qp           *qp;
    struct {
        ucs_mpool_h          mp;
        unsigned             available;
    } rx;
    struct {
        ucs_mpool_h          mp;
        unsigned             available;
        /* TODO: move to base class as this is common with rc */
        unsigned             unsignaled;
        ucs_queue_head_t     pending_ops;
    } tx;
    struct {
        unsigned             tx_qp_len;
        unsigned             rx_max_batch;
    } config;
    ucs_ptr_array_t       eps;
    uct_ud_iface_peer_t  *peers[UCT_UD_HASH_SIZE]; 
};

UCS_CLASS_DECLARE(uct_ud_iface_t, uct_iface_ops_t*, uct_worker_h, const char *,
                  unsigned, unsigned, uct_ud_iface_config_t*)

struct uct_ud_ctl_hdr {
    uint8_t type;
    uint8_t reserved[3];
    union {
        struct {
            uct_ud_iface_addr_t if_addr;
            uct_ud_ep_addr_t    ep_addr;
            uint32_t            conn_id;
        } conn_req;
        struct {
            uint32_t src_ep_id;
        } conn_rep;
        uint32_t data;
    };
} UCS_S_PACKED;


extern ucs_config_field_t uct_ud_iface_config_table[];

void uct_ud_iface_query(uct_ud_iface_t *iface, uct_iface_attr_t *iface_attr);

ucs_status_t uct_ud_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *iface_addr);

void uct_ud_iface_add_ep(uct_ud_iface_t *iface, uct_ud_ep_t *ep);
void uct_ud_iface_remove_ep(uct_ud_iface_t *iface, uct_ud_ep_t *ep);
void uct_ud_iface_replace_ep(uct_ud_iface_t *iface, uct_ud_ep_t *old_ep, uct_ud_ep_t *new_ep);

ucs_status_t uct_ud_iface_flush(uct_iface_h tl_iface);

static inline int uct_ud_iface_can_tx(uct_ud_iface_t *iface)
{
    if (iface->tx.available == 0) {
        ucs_trace_poll("iface=%p out of tx wqe", iface);
        return 0;
    }
    return 1;
}

/* 
management of connecting endpoints (cep) 

Such endpoint are created either by explicitely calling connect_to_iface()
or implicitely as a result of UD connection protocol. Calling 
connect_to_iface() may reuse already existing endpoint that was implicitely
created.

UD connection protocol

The protocol allows connection establishment in environment where UD packets
can be dropped, duplicated or reordered. The connection is done as 3 way
handshake:

1: CREQ (src_if_addr, src_ep_addr, conn_id) 
Connection request. It includes source interface address, source ep address
and connection id.

Connection id is essentially a counter of endpoints that are created by
connect_to_iface(). The counter is per destination interface. Purpose of
conn_id is to ensure order between multiple CREQ packets and to handle
simultanuous connection establishment. The case when both sides call
connect_to_iface(). The rule is that connected endpoints must have
same conn_id.

2: CREP (dest_ep_id) 

Connection reply. It includes id of destination endpoint and optinally ACK
request flag. From this point reliability is handled by UD protocol as
source and destination endpoint ids are known.

Endpoint may be created upon reception of CREQ. It is possible that the
endpoint already exists because CREQ is retransmitted or because of
simultaneous connection. In any case endpoint connection id must be
equal to connection id in CREQ.

3: ACK

Ack on connection reply. It may be send as part of the data packet.

Implicit endpoints reuse

Endpoints created upon receive of CREP request can be re-used when
application calls connect_to_iface(). 

Data structure

Two level hash table:
(src_if_addr) -> peer (conn_id)->ep

Connection id assignment:

  0 1 ... conn_last_id, +1, +2, ... UCT_UD_EP_CONN_ID_MAX

Ids upto (not including) conn_last_id are already assigned to endpoints. 
Any endpoint with conn_id >= conn_last_id is created on receive of CREQ 
There may be holes because CREQs are not received in order.

Call to connect_to_iface() will try reuse endpoint with 
conn_id = conn_last_id

If there is no such endpoint new endpoint with id conn_last_id
will be created. 

In both cases conn_last_id = conn_last_id + 1

*/
void uct_ud_iface_cep_init(uct_ud_iface_t *iface);

/* find ep that is connected to (src_if, src_ep) */
uct_ud_ep_t *uct_ud_iface_cep_lookup(uct_ud_iface_t *iface, uct_ud_iface_addr_t *src_if_addr, uint32_t conn_id);

/* remove ep */
void uct_ud_iface_cep_remove(uct_ud_ep_t *ep);

/* replace already existing ep, new_ep must be setup by caller */
typedef void (*uct_ud_ep_copy_func_t)(uct_ud_ep_t *old_ep, uct_ud_ep_t *new_ep);
void uct_ud_iface_cep_replace(uct_ud_ep_t *old_ep, uct_ud_ep_t *new_ep, uct_ud_ep_copy_func_t f);

/* insert new ep that is connected to src_if_addr */
ucs_status_t uct_ud_iface_cep_insert(uct_ud_iface_t *iface, uct_ud_iface_addr_t *src_if_addr, uct_ud_ep_t *ep, uint32_t conn_id);

void uct_ud_iface_cep_cleanup(uct_ud_iface_t *iface);
#endif

