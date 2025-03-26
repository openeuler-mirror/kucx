/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#ifndef UCT_SDMA_MD_H_
#define UCT_SDMA_MD_H_

#include <ucs/config/types.h>
#include <ucs/type/status.h>
#include <uct/base/uct_md.h>

#include "mdk_sdma.h"

#define PATH_SYS_CPU "/sys/devices/system/cpu/cpu%d/topology/core_siblings"
#define PATH_CTX_SIZE 100

extern uct_component_t uct_sdma_component;

typedef int (*sdma_pin_mem_func)(int fd, void *vma, uint32_t size, uint64_t *cookie);
typedef int (*sdma_unpin_mem_func)(int fd, uint64_t cookie);

typedef struct uct_sdma_md {
    struct uct_md super;           /**< Domain info */
    int max_num_devices;
    int num_devices;               /* Number of devices to create */
    int *sdma_fd;                  /**< File descriptor for SDMA_DEV_NAME */
    sdma_pin_mem_func pin_umem_cb;     /* pin mem handler */
    sdma_unpin_mem_func unpin_umem_cb; /* unpin mem handler */
} uct_sdma_md_t;

typedef struct uct_sdma_md_config {
    uct_md_config_t super;
    uint32_t dev_name_len;
    uint32_t dev_num;
} uct_sdma_md_config_t;

typedef struct uct_sdma_key {
    void *address; /**< base addr for the registration */
    uint64_t cookie;
} uct_sdma_key_t;

ucs_status_t uct_sdma_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr);

ucs_status_t uct_sdma_mem_alloc(uct_md_h tl_md, size_t *length_p, void **address_p, ucs_memory_type_t mem_type,
                                unsigned flags, const char *alloc_name, uct_mem_h *memh_p);

ucs_status_t uct_sdma_mem_free(uct_md_h md, uct_mem_h memh);

ucs_status_t uct_sdma_mem_reg(uct_md_h md, void *address, size_t length, const uct_md_mem_reg_params_t *params, uct_mem_h *memh_p);

ucs_status_t uct_sdma_mem_dereg(uct_md_h md, const uct_md_mem_dereg_params_t *params);

void uct_sdma_md_close(uct_md_h md);

#endif