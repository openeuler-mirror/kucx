/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2019.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "uct_component.h"

#include <ucs/debug/assert.h>
#include <ucs/debug/memtrack.h>
#include <ucs/sys/module.h>
#include <ucs/sys/string.h>
#include <limits.h>
#include <string.h>


ucs_status_t uct_query_components(uct_component_h **components_p,
                                  unsigned *num_components_p)
{
    UCS_MODULE_FRAMEWORK_DECLARE(uct);
    uct_component_h *components;
    uct_md_component_t *mdc;
    size_t num_components;

    UCS_MODULE_FRAMEWORK_LOAD(uct, 0);
    num_components = ucs_list_length(&uct_md_components_list);
    components = ucs_malloc(num_components * sizeof(*components),
                            "uct_components");
    if (components == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    ucs_assert(num_components < UINT_MAX);
    *num_components_p = num_components;
    *components_p     = components;

    ucs_list_for_each(mdc, &uct_md_components_list, list) {
       *(components++) = mdc;
    }

    return UCS_OK;
}

void uct_release_component_list(uct_component_h *components)
{
    ucs_free(components);
}

ucs_status_t uct_component_query(uct_component_h component,
                                 uct_component_attr_t *component_attr)
{
    uct_md_component_t *mdc = component;
    uct_md_resource_desc_t *resources = NULL;
    unsigned num_resources = 0;
    ucs_status_t status;

    if (component_attr->field_mask & (UCT_COMPONENT_ATTR_FIELD_MD_RESOURCE_COUNT|
                                      UCT_COMPONENT_ATTR_FIELD_MD_RESOURCES)) {
        // TODO change definition of md->query_resources
        status = mdc->query_resources(&resources, &num_resources);
        if (status != UCS_OK) {
            return status;
        }

        ucs_assertv((num_resources == 0) || (resources != NULL),
                    "component=%s", mdc->name);
    }

    if (component_attr->field_mask & UCT_COMPONENT_ATTR_FIELD_NAME) {
        ucs_snprintf_zero(component_attr->name, sizeof(component_attr->name),
                          "%s", mdc->name);
    }

    if (component_attr->field_mask & UCT_COMPONENT_ATTR_FIELD_MD_RESOURCE_COUNT) {
        component_attr->md_resource_count = num_resources;

    }

    if ((resources != NULL) &&
        (component_attr->field_mask & UCT_COMPONENT_ATTR_FIELD_MD_RESOURCES))
    {
        memcpy(component_attr->md_resources, resources,
               sizeof(uct_md_resource_desc_t) * num_resources);
    }

    ucs_free(resources);
    return UCS_OK;
}
