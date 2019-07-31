/**
 * Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCS_MEMTYPE_CACHE_H_
#define UCS_MEMTYPE_CACHE_H_

#include "memory_type.h"

#include <ucs/datastruct/pgtable.h>
#include <ucs/datastruct/list.h>
#include <ucs/stats/stats_fwd.h>
#include <ucs/sys/compiler_def.h>


BEGIN_C_DECLS

typedef struct ucs_memtype_cache         ucs_memtype_cache_t;
typedef struct ucs_memtype_cache_region  ucs_memtype_cache_region_t;


struct ucs_memtype_cache_region {
    ucs_pgt_region_t    super;    /**< Base class - page table region */
    ucs_list_link_t     list;     /**< List element */
    ucs_memory_type_t   mem_type; /**< Memory type the address belongs to */
};


struct ucs_memtype_cache {
    pthread_rwlock_t      lock;       /**< protests the page table */
    ucs_pgtable_t         pgtable;    /**< Page table to hold the regions */
};


/**
 * Create a memtype cache.
 *
 * @param [out] memtype_cache_p Filled with a pointer to the memtype cache.
 */
ucs_status_t ucs_memtype_cache_create(ucs_memtype_cache_t **memtype_cache_p);


/**
 * Destroy a memtype cache.
 *
 * @param [in]  memtype_cache       Memtype cache to destroy.
 */
void ucs_memtype_cache_destroy(ucs_memtype_cache_t *memtype_cache);


/** Find if address range is in memtype cache.
 *
 * @param [in]  memtype_cache   Memtype cache to search
 * @param [in]  address         Address to lookup
 * @param [in]  length          Length of the memory
 * @param [out] ucm_mem_type    Memory type of the address
 *
 * @return Error code.
 */
ucs_status_t ucs_memtype_cache_lookup(ucs_memtype_cache_t *memtype_cache, void *address,
                                      size_t length, ucs_memory_type_t *mem_type);

END_C_DECLS

#endif
