/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
*
* $COPYRIGHT$
* $HEADER$
*/

#include <ucs/gtest/test.h>
extern "C" {
#include <uct/api/uct.h>
}


class test_uct : public ucs::test {
};


UCS_TEST_F(test_uct, query_resources) {
    ucs_status_t status;
    uct_context_h ucth;
    uct_resource_desc_t *resources;
    unsigned num_resources;

    ucth = NULL;
    status = uct_init(&ucth);
    ASSERT_UCS_OK(status);
    ASSERT_TRUE(ucth != NULL);

    status = uct_query_resources(ucth, &resources, &num_resources);
    ASSERT_UCS_OK(status);

    for (unsigned i = 0; i < num_resources; ++i) {
        uct_resource_desc_t *res = &resources[i];
        EXPECT_TRUE(strcmp(res->tl_name, ""));
        EXPECT_TRUE(strcmp(res->hw_name, ""));
        EXPECT_GT(res->latency, 0);
        EXPECT_GT(res->bandwidth, 0);
        UCS_TEST_MESSAGE << i << ": " << res->tl_name <<
                        " on " << res->hw_name <<
                        " at " << (res->bandwidth / 1024.0 / 1024.0) << " MB/sec";
    }

    uct_release_resource_list(resources);

    uct_cleanup(ucth);
}

UCS_TEST_F(test_uct, open_iface) {
    ucs_status_t status;
    uct_context_h ucth;
    uct_resource_desc_t *resources;
    unsigned num_resources;

    ucth = NULL;
    status = uct_init(&ucth);
    ASSERT_UCS_OK(status);
    ASSERT_TRUE(ucth != NULL);

    status = uct_query_resources(ucth, &resources, &num_resources);
    ASSERT_UCS_OK(status);

    for (unsigned i = 0; i < num_resources; ++i) {
        uct_iface_h iface = NULL;
        status = uct_iface_open(ucth, resources[i].tl_name, resources[i].hw_name,
                                &iface);
        ASSERT_TRUE(iface != NULL);
        ASSERT_UCS_OK(status);

        uct_iface_close(iface);
    }

    uct_release_resource_list(resources);

    uct_cleanup(ucth);
}
