/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
* Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_CMA_PD_H_
#define UCT_CMA_PD_H_

#include <ucs/config/types.h>
#include <ucs/debug/memtrack.h>
#include <ucs/type/status.h>
#include <uct/base/uct_pd.h>

#include <sys/types.h>
#include <unistd.h>

extern uct_pd_component_t uct_cma_pd_component;

ucs_status_t uct_cma_pd_query(uct_pd_h pd, uct_pd_attr_t *pd_attr);

#endif
