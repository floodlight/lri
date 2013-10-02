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

#ifndef __FORWARDING_CONFIG_H__
#define __FORWARDING_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif

#ifdef FORWARDING_INCLUDE_CUSTOM_CONFIG
#include <forwarding_custom_config.h>
#endif


#ifndef FORWARDING_CONFIG_INCLUDE_UCLI
#define FORWARDING_CONFIG_INCLUDE_UCLI 1
#endif



/* <auto.start.cdefs(FORWARDING_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * FORWARDING_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef FORWARDING_CONFIG_INCLUDE_LOGGING
#define FORWARDING_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT
#define FORWARDING_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * FORWARDING_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef FORWARDING_CONFIG_LOG_BITS_DEFAULT
#define FORWARDING_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define FORWARDING_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * FORWARDING_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef FORWARDING_CONFIG_PORTING_STDLIB
#define FORWARDING_CONFIG_PORTING_STDLIB 1
#endif

/**
 * FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS FORWARDING_CONFIG_PORTING_STDLIB
#endif

/**
 * FORWARDING_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef FORWARDING_CONFIG_INCLUDE_UCLI
#define FORWARDING_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct forwarding_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} forwarding_config_settings_t;

/** Configuration settings table. */
/** forwarding_config_settings table. */
extern forwarding_config_settings_t forwarding_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* forwarding_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int forwarding_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(FORWARDING_CONFIG_HEADER).header> */



#endif /* __FORWARDING_CONFIG_H__ */
