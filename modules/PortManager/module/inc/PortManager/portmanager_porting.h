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
 * @brief PortManager Porting Macros.
 * 
 * @addtogroup portmanager_porting
 * @{
 * 
 ***************************************************************/

#ifndef __PORTMANAGER_PORTING_H__
#define __PORTMANAGER_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if PORTMANAGER_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef PORTMANAGER_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define PORTMANAGER_MEMSET GLOBAL_MEMSET
    #elif PORTMANAGER_CONFIG_PORTING_STDLIB == 1
        #define PORTMANAGER_MEMSET memset
    #else
        #error The macro PORTMANAGER_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef PORTMANAGER_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define PORTMANAGER_MEMCPY GLOBAL_MEMCPY
    #elif PORTMANAGER_CONFIG_PORTING_STDLIB == 1
        #define PORTMANAGER_MEMCPY memcpy
    #else
        #error The macro PORTMANAGER_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef PORTMANAGER_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define PORTMANAGER_STRNCPY GLOBAL_STRNCPY
    #elif PORTMANAGER_CONFIG_PORTING_STDLIB == 1
        #define PORTMANAGER_STRNCPY strncpy
    #else
        #error The macro PORTMANAGER_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef PORTMANAGER_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define PORTMANAGER_STRLEN GLOBAL_STRLEN
    #elif PORTMANAGER_CONFIG_PORTING_STDLIB == 1
        #define PORTMANAGER_STRLEN strlen
    #else
        #error The macro PORTMANAGER_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __PORTMANAGER_PORTING_H__ */
/* @} */
