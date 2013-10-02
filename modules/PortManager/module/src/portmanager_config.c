/****************************************************************
 * 
 *        Copyright 2013, Big Switch Networks, Inc. 
 * 
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *        http://www.eclipse.org/legal/epl-v10.html
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 * 
 ***************************************************************/

#include <PortManager/portmanager_config.h>
#include <PortManager/portmanager.h>
#include "portmanager_int.h" 
#include "portmanager_log.h"
#include <stdlib.h>
#include <cjson/cJSON.h>
#include <Configuration/configuration.h>

/* <auto.start.cdefs(PORTMANAGER_CONFIG_HEADER).source> */
#define __portmanager_config_STRINGIFY_NAME(_x) #_x
#define __portmanager_config_STRINGIFY_VALUE(_x) __portmanager_config_STRINGIFY_NAME(_x)
portmanager_config_settings_t portmanager_config_settings[] =
{
#ifdef PORTMANAGER_CONFIG_INCLUDE_LOGGING
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_INCLUDE_LOGGING), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_INCLUDE_LOGGING) },
#else
{ PORTMANAGER_CONFIG_INCLUDE_LOGGING(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_LOG_OPTIONS_DEFAULT
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_LOG_OPTIONS_DEFAULT), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ PORTMANAGER_CONFIG_LOG_OPTIONS_DEFAULT(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_LOG_BITS_DEFAULT
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_LOG_BITS_DEFAULT), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_LOG_BITS_DEFAULT) },
#else
{ PORTMANAGER_CONFIG_LOG_BITS_DEFAULT(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ PORTMANAGER_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_PORTING_STDLIB
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_PORTING_STDLIB), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_PORTING_STDLIB) },
#else
{ PORTMANAGER_CONFIG_PORTING_STDLIB(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ PORTMANAGER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef PORTMANAGER_CONFIG_INCLUDE_UCLI
    { __portmanager_config_STRINGIFY_NAME(PORTMANAGER_CONFIG_INCLUDE_UCLI), __portmanager_config_STRINGIFY_VALUE(PORTMANAGER_CONFIG_INCLUDE_UCLI) },
#else
{ PORTMANAGER_CONFIG_INCLUDE_UCLI(__portmanager_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __portmanager_config_STRINGIFY_VALUE
#undef __portmanager_config_STRINGIFY_NAME

const char*
portmanager_config_lookup(const char* setting)
{
    int i;
    for(i = 0; portmanager_config_settings[i].name; i++) {
        if(strcmp(portmanager_config_settings[i].name, setting)) {
            return portmanager_config_settings[i].value;
        }
    }
    return NULL;
}

int
portmanager_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; portmanager_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", portmanager_config_settings[i].name, portmanager_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(PORTMANAGER_CONFIG_HEADER).source> */

static int
str2mac(const char *str, of_mac_addr_t *mac)
{
    unsigned int imac[6];
    int p;
    int i;

    p = sscanf(str,"%2x:%2x:%2x:%2x:%2x:%2x",
               &imac[0], &imac[1], &imac[2], &imac[3], &imac[4], &imac[5]);
    if (p == 6) {
        for (i = 0; i < 6; i++) {
            mac->addr[i] = imac[i];
        }

        return 0;
    }

    return -1;
}

static struct {
    uint32_t log_flags;
    char mac_base_valid;
    of_mac_addr_t mac_base;
} staged_config;

static indigo_error_t
ind_port_cfg_stage(cJSON *config)
{
    char *str;
    indigo_error_t err;

    err = ind_cfg_parse_loglevel(config, "logging.dataplane",
                                 PORTMANAGER_CONFIG_LOG_BITS_DEFAULT,
                                 &staged_config.log_flags);
    if (err != INDIGO_ERROR_NONE) {
        return err;
    }

    /* Not supporting setting log options yet */

    if (ind_cfg_lookup_string(config, "of_mac_addr_base", &str) == 0) {
        if (str2mac(str, &staged_config.mac_base) == 0) {
            staged_config.mac_base_valid = 1;
        } else {
            AIM_LOG_ERROR("Config: of_mac_addr_base must be a colon sep MAC str");
        }
    } else {
        AIM_LOG_WARN("Config: Could not parse of_mac_addr_base");
    }

    return INDIGO_ERROR_NONE;
}

static void
ind_port_cfg_commit(void)
{
    aim_log_t *lobj;

    if ((lobj = aim_log_find("portmanager")) == NULL) {
        AIM_LOG_WARN("Could not find log module");
    } else {
        lobj->common_flags = staged_config.log_flags;
    }

    if (staged_config.mac_base_valid) {
        (void)ind_port_base_mac_addr_set(&staged_config.mac_base);
    }
}

const struct ind_cfg_ops ind_port_cfg_ops = {
    .stage = ind_port_cfg_stage,
    .commit = ind_port_cfg_commit,
};
