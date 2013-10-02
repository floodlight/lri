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
/************************************************************//**
 * 
 * @file
 * @brief Forwarding Porting Macros.
 * 
 * @addtogroup forwarding_porting
 * @{
 * 
 ***************************************************************/

#ifndef __FORWARDING_PORTING_H__
#define __FORWARDING_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if FORWARDING_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef FORWARDING_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define FORWARDING_MEMSET GLOBAL_MEMSET
    #elif FORWARDING_CONFIG_PORTING_STDLIB == 1
        #define FORWARDING_MEMSET memset
    #else
        #error The macro FORWARDING_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef FORWARDING_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define FORWARDING_MEMCPY GLOBAL_MEMCPY
    #elif FORWARDING_CONFIG_PORTING_STDLIB == 1
        #define FORWARDING_MEMCPY memcpy
    #else
        #error The macro FORWARDING_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef FORWARDING_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define FORWARDING_STRNCPY GLOBAL_STRNCPY
    #elif FORWARDING_CONFIG_PORTING_STDLIB == 1
        #define FORWARDING_STRNCPY strncpy
    #else
        #error The macro FORWARDING_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef FORWARDING_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define FORWARDING_STRLEN GLOBAL_STRLEN
    #elif FORWARDING_CONFIG_PORTING_STDLIB == 1
        #define FORWARDING_STRLEN strlen
    #else
        #error The macro FORWARDING_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __FORWARDING_PORTING_H__ */
/* @} */
