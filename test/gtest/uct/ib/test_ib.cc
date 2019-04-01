/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
* Copyright (C) UT-Battelle, LLC. 2014. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#include <common/test.h>
#include <uct/uct_test.h>

extern "C" {
#include <poll.h>
#include <uct/api/uct.h>
#include <ucs/time/time.h>
#include <uct/ib/base/ib_device.h>
#include <uct/ib/base/ib_iface.h>
#include <uct/ib/base/ib_md.h>
}


class test_uct_ib : public uct_test {
public:
    void initialize() {
        uct_test::init();

        m_e1 = uct_test::create_entity(0);
        m_entities.push_back(m_e1);

        m_e2 = uct_test::create_entity(0);
        m_entities.push_back(m_e2);

        m_e1->connect(0, *m_e2, 0);
        m_e2->connect(0, *m_e1, 0);

        test_uct_ib::ib_am_handler_counter = 0;
    }

    typedef struct {
        unsigned length;
        /* data follows */
    } recv_desc_t;

    typedef struct {
        unsigned have_pkey; /* if 1 - means that the configured pkey was found */
        unsigned have_lmc;  /* if 1 - means that the lmc is higher than zero */
#if HAVE_DECL_IBV_LINK_LAYER_ETHERNET
        unsigned have_valid_gid_idx;
#endif
    } ib_port_desc_t;

    static ucs_status_t ib_am_handler(void *arg, void *data, size_t length,
                                      unsigned flags) {
        recv_desc_t *my_desc  = (recv_desc_t *) arg;
        uint64_t *test_ib_hdr = (uint64_t *) data;
        uint64_t *actual_data = (uint64_t *) test_ib_hdr + 1;
        unsigned data_length  = length - sizeof(test_ib_hdr);

        my_desc->length = data_length;
        if (*test_ib_hdr == 0xbeef) {
            memcpy(my_desc + 1, actual_data , data_length);
        }
        ++test_uct_ib::ib_am_handler_counter;
        return UCS_OK;
    }

    void pkey_find(const char *dev_name, unsigned port_num, struct ibv_port_attr port_attr,
                  struct ibv_context *ibctx, ib_port_desc_t *port_desc) {
         uint16_t table_idx, pkey, pkey_partition;
         uct_ib_iface_config_t *ib_config = ucs_derived_of(m_iface_config, uct_ib_iface_config_t);

         /* check if the configured pkey exists in the port's pkey table */
           for (table_idx = 0; table_idx < port_attr.pkey_tbl_len; table_idx++) {
               if(ibv_query_pkey(ibctx, port_num, table_idx, &pkey)) {
                   UCS_TEST_ABORT("Failed to query pkey on port " << port_num << " on device: " << dev_name);
               }
               pkey_partition = ntohs(pkey) & UCT_IB_PKEY_PARTITION_MASK;
               if (pkey_partition == (ib_config->pkey_value & UCT_IB_PKEY_PARTITION_MASK)) {
                   port_desc->have_pkey = 1;
                   break;
               }
           }
    }

#if HAVE_DECL_IBV_LINK_LAYER_ETHERNET
    void test_eth_port(struct ibv_device *device, struct ibv_port_attr port_attr,
                       struct ibv_context *ibctx, unsigned port_num,
                       ib_port_desc_t *port_desc) {

        union ibv_gid gid;
        uct_ib_md_config_t *md_config = ucs_derived_of(m_md_config, uct_ib_md_config_t);
        char md_name[UCT_MD_NAME_MAX];
        uct_md_h uct_md;
        uct_ib_md_t *ib_md;
        ucs_status_t status;
        uint8_t gid_index;

        /* no pkeys for Ethernet */
        port_desc->have_pkey = 0;

        uct_ib_make_md_name(md_name, device);

        status = uct_ib_md_open(md_name, m_md_config, &uct_md);
        ASSERT_UCS_OK(status);

        ib_md = ucs_derived_of(uct_md, uct_ib_md_t);
        status = uct_ib_device_select_gid_index(&ib_md->dev,
                                                port_num, md_config->ext.gid_index,
                                                &gid_index);
        ASSERT_UCS_OK(status);

        /* check the gid index */
        if (ibv_query_gid(ibctx, port_num, gid_index, &gid) != 0) {
            UCS_TEST_ABORT("Failed to query gid (index=" << gid_index << ")");
        }
        if (uct_ib_device_is_gid_raw_empty(gid.raw)) {
            port_desc->have_valid_gid_idx = 0;
        } else {
            port_desc->have_valid_gid_idx = 1;
        }

        uct_ib_md_close(uct_md);
    }
#endif

    void lmc_find(struct ibv_port_attr port_attr, ib_port_desc_t *port_desc) {

         if (port_attr.lmc > 0) {
             port_desc->have_lmc = 1;
         }
    }

    void port_attr_test(const char *dev_name, unsigned port_num, ib_port_desc_t *port_desc) {
        struct ibv_device **device_list;
        struct ibv_context *ibctx = NULL;
        struct ibv_port_attr port_attr;
        int num_devices, i, found = 0;

        /* get device list */
        device_list = ibv_get_device_list(&num_devices);
        if (device_list == NULL) {
            UCS_TEST_ABORT("Failed to get the device list.");
        }

        /* search for the given device in the device list */
        for (i = 0; i < num_devices; ++i) {
            if (strcmp(device_list[i]->name, dev_name)) {
                continue;
            }
            /* found this dev_name on the host - open it */
            ibctx = ibv_open_device(device_list[i]);
            if (ibctx == NULL) {
                UCS_TEST_ABORT("Failed to open the device.");
            }
            found = 1;
            break;
        }
        if (found != 1) {
            UCS_TEST_ABORT("The requested device: " << dev_name << ", wasn't found in the device list.");
        }

        if (ibv_query_port(ibctx, port_num, &port_attr) != 0) {
            UCS_TEST_ABORT("Failed to query port " << port_num << " on device: " << dev_name);
        }

        /* check the lmc value in the port */
        lmc_find(port_attr, port_desc);

        if (IBV_PORT_IS_LINK_LAYER_ETHERNET(&port_attr)) {
            test_eth_port(device_list[i], port_attr, ibctx, port_num, port_desc);
            goto out;
        }

        /* find the configured pkey */
        pkey_find(dev_name, port_num, port_attr, ibctx, port_desc);

out:
        ibv_close_device(ibctx);
        ibv_free_device_list(device_list);
    }

    void test_port_avail(ib_port_desc_t *port_desc) {
        char *p, *dev_name;
        unsigned port_num;

        dev_name = strdup(GetParam()->dev_name.c_str()); /* device name and port number */
        /* split dev_name */
        p = strchr(dev_name, ':');
        EXPECT_TRUE(p != NULL);
        *p = 0;

        /* dev_name holds the device name */
        /* port number */
        if (sscanf(p + 1, "%d", &port_num) != 1) {
            UCS_TEST_ABORT("Failed to get the port number on device: " << dev_name);
        }
        port_attr_test(dev_name, port_num, port_desc);

        free(dev_name);
    }

    void test_address_pack(uint64_t subnet_prefix) {
        uct_ib_iface_t *iface = ucs_derived_of(m_e1->iface(), uct_ib_iface_t);
        static const uint16_t lid_in = 0x1ee7;
        union ibv_gid gid_in, gid_out;
        uct_ib_address_t *ib_addr;
        uint16_t lid_out;

        ib_addr = (uct_ib_address_t*)malloc(uct_ib_address_size(iface));

        gid_in.global.subnet_prefix = subnet_prefix;
        gid_in.global.interface_id  = 0xdeadbeef;
        uct_ib_address_pack(iface, &gid_in, lid_in, ib_addr);

        uct_ib_address_unpack(ib_addr, &lid_out, &gid_out);

        if (uct_ib_iface_is_roce(iface)) {
            EXPECT_TRUE(iface->is_global_addr);
        } else {
            EXPECT_EQ(lid_in, lid_out);
        }

        if (iface->is_global_addr) {
            EXPECT_EQ(gid_in.global.subnet_prefix, gid_out.global.subnet_prefix);
            EXPECT_EQ(gid_in.global.interface_id,  gid_out.global.interface_id);
        }

        free(ib_addr);
    }

    void send_recv_short() {
        uint64_t send_data   = 0xdeadbeef;
        uint64_t test_ib_hdr = 0xbeef;
        recv_desc_t *recv_buffer;

        initialize();
        check_caps(UCT_IFACE_FLAG_AM_SHORT);

        recv_buffer = (recv_desc_t *) malloc(sizeof(*recv_buffer) + sizeof(uint64_t));
        recv_buffer->length = 0; /* Initialize length to 0 */

        /* set a callback for the uct to invoke for receiving the data */
        uct_iface_set_am_handler(m_e2->iface(), 0, ib_am_handler , recv_buffer, 0);

        /* send the data */
        uct_ep_am_short(m_e1->ep(0), 0, test_ib_hdr, &send_data, sizeof(send_data));

        short_progress_loop(100.0);

        ASSERT_EQ(sizeof(send_data), recv_buffer->length);
        EXPECT_EQ(send_data, *(uint64_t*)(recv_buffer+1));

        free(recv_buffer);
    }

    uct_ib_device_t *ib_device(entity *entity) {
        uct_ib_iface_t *iface = ucs_derived_of(entity->iface(), uct_ib_iface_t);
        return uct_ib_iface_device(iface);
    }

protected:
    entity *m_e1, *m_e2;
    static size_t ib_am_handler_counter;
};

size_t test_uct_ib::ib_am_handler_counter = 0;

UCS_TEST_P(test_uct_ib, non_default_pkey, "IB_PKEY=0x2")
{
    ib_port_desc_t *port_desc;

    /* check if the configured pkey exists in the port's pkey table.
     * skip this test if it doesn't. */
    port_desc = (ib_port_desc_t *) calloc(1, sizeof(*port_desc));
    test_port_avail(port_desc);

    if (port_desc->have_pkey) {
        free(port_desc);
    } else {
        free(port_desc);
        UCS_TEST_SKIP_R("pkey not found or not an IB port");
    }

    send_recv_short();
}

UCS_TEST_P(test_uct_ib, non_default_lmc, "IB_LID_PATH_BITS=1")
{
    ib_port_desc_t *port_desc;

    /* check if a non zero lmc is set on the port.
     * skip this test if it isn't. */
    port_desc = (ib_port_desc_t *) calloc(1, sizeof(*port_desc));
    test_port_avail(port_desc);

    if (port_desc->have_lmc) {
        free(port_desc);
    } else {
        free(port_desc);
        UCS_TEST_SKIP_R("lmc is set to zero on an IB port");
    }

    send_recv_short();
}

#if HAVE_DECL_IBV_LINK_LAYER_ETHERNET
UCS_TEST_P(test_uct_ib, non_default_gid_idx, "GID_INDEX=1")
{
    ib_port_desc_t *port_desc;

    /* check if a non zero gid index can be used on the port.
     * skip this test if it cannot. */
    port_desc = (ib_port_desc_t *) calloc(1, sizeof(*port_desc));
    test_port_avail(port_desc);

    if (port_desc->have_valid_gid_idx) {
        free(port_desc);
    } else {
        free(port_desc);
        UCS_TEST_SKIP_R("the configured gid index (1) cannot be used on the port");
    }

    send_recv_short();
}
#endif

UCS_TEST_P(test_uct_ib, address_pack) {
    initialize();
    test_address_pack(UCT_IB_LINK_LOCAL_PREFIX);
    test_address_pack(UCT_IB_SITE_LOCAL_PREFIX | htobe64(0x7200));
    test_address_pack(0xdeadfeedbeefa880ul);
}


UCT_INSTANTIATE_IB_TEST_CASE(test_uct_ib);


class test_uct_ib_utils : public ucs::test {
};

UCS_TEST_F(test_uct_ib_utils, sec_to_qp_time) {
    double avg;
    uint8_t qp_val;

    // 0 sec
    qp_val = uct_ib_to_qp_fabric_time(0);
    EXPECT_EQ(1, qp_val);

    // the average time defined for the [0, 1st element]
    qp_val = uct_ib_to_qp_fabric_time(4.096 * pow(2, 0) / UCS_USEC_PER_SEC);
    EXPECT_EQ(1, qp_val);

    // the time defined for the 1st element
    qp_val = uct_ib_to_qp_fabric_time(4.096 * pow(2, 1) / UCS_USEC_PER_SEC);
    EXPECT_EQ(1, qp_val);

    for (uint8_t i = 2; i <= UCT_IB_FABRIC_TIME_MAX; i++) {
        // the time defined for the (i)th element
        qp_val = uct_ib_to_qp_fabric_time(4.096 * pow(2, i) / UCS_USEC_PER_SEC);
        EXPECT_EQ(i % UCT_IB_FABRIC_TIME_MAX, qp_val);

        // avg = (the average time defined for the [(i - 1)th element, (i)th element])
        avg = (4.096 * pow(2, i - 1) + 4.096 * pow(2, i)) * 0.5;
        qp_val = uct_ib_to_qp_fabric_time(avg / UCS_USEC_PER_SEC);
        EXPECT_EQ(i % UCT_IB_FABRIC_TIME_MAX, qp_val);

        // the average time defined for the [(i - 1)th element, avg]
        qp_val = uct_ib_to_qp_fabric_time((4.096 * pow(2, i - 1) + avg) * 0.5 / UCS_USEC_PER_SEC);
        EXPECT_EQ((i - 1) % UCT_IB_FABRIC_TIME_MAX, qp_val);

        // the average time defined for the [avg, (i)th element]
        qp_val = uct_ib_to_qp_fabric_time((avg +  4.096 * pow(2, i)) * 0.5 / UCS_USEC_PER_SEC);
        EXPECT_EQ(i % UCT_IB_FABRIC_TIME_MAX, qp_val);
    }
}

UCS_TEST_F(test_uct_ib_utils, sec_to_rnr_time) {
    double avg;
    uint8_t rnr_val;

    // 0 sec
    rnr_val = uct_ib_to_rnr_fabric_time(0);
    EXPECT_EQ(1, rnr_val);

    // the average time defined for the [0, 1st element]
    avg = uct_ib_qp_rnr_time_ms[1] * 0.5;
    rnr_val = uct_ib_to_rnr_fabric_time(avg / UCS_MSEC_PER_SEC);
    EXPECT_EQ(1, rnr_val);

    for (uint8_t i = 1; i < UCT_IB_FABRIC_TIME_MAX; i++) {
        // the time defined for the (i)th element
        rnr_val = uct_ib_to_rnr_fabric_time(uct_ib_qp_rnr_time_ms[i] / UCS_MSEC_PER_SEC);
        EXPECT_EQ(i, rnr_val);

        // avg = (the average time defined for the [(i)th element, (i + 1)th element])
        avg = (uct_ib_qp_rnr_time_ms[i] +
               uct_ib_qp_rnr_time_ms[(i + 1) % UCT_IB_FABRIC_TIME_MAX]) * 0.5;
        rnr_val = uct_ib_to_rnr_fabric_time(avg / UCS_MSEC_PER_SEC);
        EXPECT_EQ((i + 1) % UCT_IB_FABRIC_TIME_MAX, rnr_val);

        // the average time defined for the [(i)th element, avg]
        rnr_val = uct_ib_to_rnr_fabric_time((uct_ib_qp_rnr_time_ms[i] + avg) * 0.5 / UCS_MSEC_PER_SEC);
        EXPECT_EQ(i, rnr_val);

        // the average time defined for the [avg, (i + 1)th element]
        rnr_val = uct_ib_to_rnr_fabric_time((avg +
                                             uct_ib_qp_rnr_time_ms[(i + 1) % UCT_IB_FABRIC_TIME_MAX]) *
                                            0.5 / UCS_MSEC_PER_SEC);
        EXPECT_EQ((i + 1) % UCT_IB_FABRIC_TIME_MAX, rnr_val);
    }

    // the time defined for the biggest value
    rnr_val = uct_ib_to_rnr_fabric_time(uct_ib_qp_rnr_time_ms[0] / UCS_MSEC_PER_SEC);
    EXPECT_EQ(0, rnr_val);

    // 1 sec
    rnr_val = uct_ib_to_rnr_fabric_time(1.);
    EXPECT_EQ(0, rnr_val);
}


class test_uct_event_ib : public test_uct_ib {
public:
    test_uct_event_ib() {
        length            = 8;
        wakeup_fd.revents = 0;
        wakeup_fd.events  = POLLIN;
        wakeup_fd.fd      = 0;
        test_ib_hdr       = 0xbeef;
        m_buf1            = NULL;
        m_buf2            = NULL;
    }

    void initialize() {
        ucs_status_t status;

        test_uct_ib::initialize();

        check_caps(UCT_IFACE_FLAG_PUT_SHORT | UCT_IFACE_FLAG_CB_SYNC |
                   UCT_IFACE_FLAG_EVENT_SEND_COMP |
                   UCT_IFACE_FLAG_EVENT_RECV);

        /* create receiver wakeup */
        status = uct_iface_event_fd_get(m_e1->iface(), &wakeup_fd.fd);
        ASSERT_EQ(status, UCS_OK);

        EXPECT_EQ(0, poll(&wakeup_fd, 1, 0));

        m_buf1 = new mapped_buffer(length, 0x1, *m_e1);
        m_buf2 = new mapped_buffer(length, 0x2, *m_e2);

        /* set a callback for the uct to invoke for receiving the data */
        uct_iface_set_am_handler(m_e1->iface(), 0, ib_am_handler, m_buf1->ptr(),
                                 0);

        test_uct_event_ib::bcopy_pack_count = 0;
    }

    static size_t pack_cb(void *dest, void *arg) {
        const mapped_buffer *buf = (const mapped_buffer *)arg;
        memcpy(dest, buf->ptr(), buf->length());
        ++test_uct_event_ib::bcopy_pack_count;
        return buf->length();
    }

    /* Use put_bcopy here to provide send_cq entry */
    void send_msg_e1_e2(size_t count = 1) {
        for (size_t i = 0; i < count; ++i) {
            ssize_t status = uct_ep_put_bcopy(m_e1->ep(0), pack_cb, (void *)m_buf1,
                                              m_buf2->addr(), m_buf2->rkey());
            if (status < 0) {
                ASSERT_UCS_OK((ucs_status_t)status);
            }
        }
    }

    void send_msg_e2_e1(size_t count = 1) {
        for (size_t i = 0; i < count; ++i) {
            ucs_status_t status = uct_ep_am_short(m_e2->ep(0), 0, test_ib_hdr,
                                                  m_buf2->ptr(), m_buf2->length());
            ASSERT_UCS_OK(status);
        }
    }

    void check_send_cq(uct_iface_t *iface, size_t val) {
        uct_ib_iface_t *ib_iface = ucs_derived_of(iface, uct_ib_iface_t);
        struct ibv_cq  *send_cq = ib_iface->cq[UCT_IB_DIR_TX];

        if (val != send_cq->comp_events_completed) {
            uint32_t completed_evt = send_cq->comp_events_completed;
            /* need this call to acknowledge the completion to prevent iface dtor hung*/
            ibv_ack_cq_events(ib_iface->cq[UCT_IB_DIR_TX], 1);
            UCS_TEST_ABORT("send_cq->comp_events_completed have to be 1 but the value "
                           << completed_evt);
        }
    }

    void check_recv_cq(uct_iface_t *iface, size_t val) {
        uct_ib_iface_t *ib_iface = ucs_derived_of(iface, uct_ib_iface_t);
        struct ibv_cq  *recv_cq = ib_iface->cq[UCT_IB_DIR_RX];

        if (val != recv_cq->comp_events_completed) {
            uint32_t completed_evt = recv_cq->comp_events_completed;
            /* need this call to acknowledge the completion to prevent iface dtor hung*/
            ibv_ack_cq_events(ib_iface->cq[UCT_IB_DIR_RX], 1);
            UCS_TEST_ABORT("recv_cq->comp_events_completed have to be 1 but the value "
                           << completed_evt);
        }
    }

    void cleanup() {
        delete(m_buf1);
        delete(m_buf2);
        test_uct_ib::cleanup();
    }

protected:
    static const unsigned EVENTS = UCT_EVENT_RECV | UCT_EVENT_SEND_COMP;

    struct pollfd wakeup_fd;
    size_t length;
    uint64_t test_ib_hdr;
    mapped_buffer *m_buf1, *m_buf2;
    static size_t bcopy_pack_count;
};

size_t test_uct_event_ib::bcopy_pack_count = 0;


UCS_TEST_P(test_uct_event_ib, tx_cq)
{
    ucs_status_t status;

    initialize();

    status = uct_iface_event_arm(m_e1->iface(), EVENTS);
    ASSERT_EQ(status, UCS_OK);

    /* check initial state of the fd and [send|recv]_cq */
    EXPECT_EQ(0, poll(&wakeup_fd, 1, 0));
    check_send_cq(m_e1->iface(), 0);
    check_recv_cq(m_e1->iface(), 0);

    /* send the data */
    send_msg_e1_e2();

    /* make sure the file descriptor is signaled once */
    ASSERT_EQ(1, poll(&wakeup_fd, 1, 1000*ucs::test_time_multiplier()));

    status = uct_iface_event_arm(m_e1->iface(), EVENTS);
    ASSERT_EQ(status, UCS_ERR_BUSY);

    /* make sure [send|recv]_cq handled properly */
    check_send_cq(m_e1->iface(), 1);
    check_recv_cq(m_e1->iface(), 0);

    m_e1->flush();
}


UCS_TEST_P(test_uct_event_ib, txrx_cq)
{
    const size_t msg_count = 1;
    ucs_status_t status;

    initialize();

    status = uct_iface_event_arm(m_e1->iface(), EVENTS);
    ASSERT_EQ(UCS_OK, status);

    /* check initial state of the fd and [send|recv]_cq */
    EXPECT_EQ(0, poll(&wakeup_fd, 1, 0));
    check_send_cq(m_e1->iface(), 0);
    check_recv_cq(m_e1->iface(), 0);

    /* send the data */
    send_msg_e1_e2(msg_count);
    send_msg_e2_e1(msg_count);

    twait(150); /* Let completion to be generated */

    /* Make sure all messages delivered */
    while ((test_uct_ib::ib_am_handler_counter   < msg_count) ||
           (test_uct_event_ib::bcopy_pack_count < msg_count)) {
        progress();
    }

    /* make sure the file descriptor is signaled */
    ASSERT_EQ(1, poll(&wakeup_fd, 1, 1000*ucs::test_time_multiplier()));

    /* Acknowledge all the requests */
    short_progress_loop();
    status = uct_iface_event_arm(m_e1->iface(), EVENTS);
    ASSERT_EQ(UCS_ERR_BUSY, status);

    /* make sure [send|recv]_cq handled properly */
    check_send_cq(m_e1->iface(), 1);
    check_recv_cq(m_e1->iface(), 1);

    m_e1->flush();
    m_e2->flush();
}


UCT_INSTANTIATE_IB_TEST_CASE(test_uct_event_ib);
