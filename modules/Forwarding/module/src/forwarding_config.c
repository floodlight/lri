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

#include <Forwarding/forwarding_config.h>
#include <Forwarding/forwarding.h>
#include "forwarding_int.h" 
#include "forwarding_log.h"
#include <stdlib.h>
#include <cjson/cJSON.h>
#include <Configuration/configuration.h>

/* <auto.start.cdefs(FORWARDING_CONFIG_HEADER).source> */
#define __forwarding_config_STRINGIFY_NAME(_x) #_x
#define __forwarding_config_STRINGIFY_VALUE(_x) __forwarding_config_STRINGIFY_NAME(_x)
forwarding_config_settings_t forwarding_config_settings[] =
{
#ifdef FORWARDING_CONFIG_INCLUDE_LOGGING
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_INCLUDE_LOGGING), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_INCLUDE_LOGGING) },
#else
{ FORWARDING_CONFIG_INCLUDE_LOGGING(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_LOG_BITS_DEFAULT
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_LOG_BITS_DEFAULT), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_LOG_BITS_DEFAULT) },
#else
{ FORWARDING_CONFIG_LOG_BITS_DEFAULT(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_PORTING_STDLIB
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_PORTING_STDLIB), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_PORTING_STDLIB) },
#else
{ FORWARDING_CONFIG_PORTING_STDLIB(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef FORWARDING_CONFIG_INCLUDE_UCLI
    { __forwarding_config_STRINGIFY_NAME(FORWARDING_CONFIG_INCLUDE_UCLI), __forwarding_config_STRINGIFY_VALUE(FORWARDING_CONFIG_INCLUDE_UCLI) },
#else
{ FORWARDING_CONFIG_INCLUDE_UCLI(__forwarding_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __forwarding_config_STRINGIFY_VALUE
#undef __forwarding_config_STRINGIFY_NAME

const char*
forwarding_config_lookup(const char* setting)
{
    int i;
    for(i = 0; forwarding_config_settings[i].name; i++) {
        if(strcmp(forwarding_config_settings[i].name, setting)) {
            return forwarding_config_settings[i].value;
        }
    }
    return NULL;
}

int
forwarding_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; forwarding_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", forwarding_config_settings[i].name, forwarding_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(FORWARDING_CONFIG_HEADER).source> */

static struct {
    uint32_t log_flags;
} staged_config;

static indigo_error_t
ind_fwd_cfg_stage(cJSON *config)
{
    indigo_error_t err;

    err = ind_cfg_parse_loglevel(config, "logging.dataplane",
                                 FORWARDING_CONFIG_LOG_BITS_DEFAULT,
                                 &staged_config.log_flags);
    if (err != INDIGO_ERROR_NONE) {
        return err;
    }

    /* Not supporting setting log options yet */

    return INDIGO_ERROR_NONE;
}

static void
ind_fwd_cfg_commit(void)
{
    aim_log_t *lobj;

    if ((lobj = aim_log_find("forwarding")) == NULL) {
        AIM_LOG_WARN("Could not find log module");
    } else {
        lobj->common_flags = staged_config.log_flags;
    }
}

const struct ind_cfg_ops ind_fwd_cfg_ops = {
    .stage = ind_fwd_cfg_stage,
    .commit = ind_fwd_cfg_commit,
};
