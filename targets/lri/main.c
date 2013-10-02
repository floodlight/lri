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
 * This file provides the most basic example for
 * configuring, initializing, and running and Indigo-based agent. 
 *
 *
 ****************************************************************/

#include <OFStateManager/ofstatemanager.h>
#include <SocketManager/socketmanager.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <PortManager/portmanager.h>
#include <Forwarding/forwarding.h>
#include <loci/loci.h>


#include <unistd.h>
#include <sys/types.h>

/**
 * Try an operation and return the error code on failure.
 */
#define TRY(op)                                                         \
    do {                                                                \
        int _rv;                                                        \
        if ((_rv = (op)) < 0) {                                         \
            fprintf(stderr, "%s: ERROR %d at %s:%d",                    \
                    #op, _rv, __FILE__, __LINE__);                      \
            return _rv;                                                 \
        }                                                               \
    } while (0)





/**
 * The maximum number of ports to support:
 */
#ifndef LRI_MAX_PORTS
#define LRI_MAX_PORTS 48
#endif

/**
 * The maximum number of flows to support:
 */
#ifndef LRI_MAX_FLOWS
#define LRI_MAX_FLOWS 1024
#endif

/**
 * The default controller connection. 
 */
#ifndef LRI_CONTROLLER_ADDRESS
#define LRI_CONTROLLER_ADDRESS "127.0.0.1"
#endif

#ifndef LRI_CONTROLLER_PORT
#define LRI_CONTROLLER_PORT 6633
#endif

/**
 * Check for root access by default
 */
#ifndef LRI_CONFIG_ROOT_ACCESS_CHECK
#define LRI_CONFIG_ROOT_ACCESS_CHECK 1
#endif

int 
aim_main(int argc, char* argv[])
{
    /** The Indigo SocketManager configuration data. */
    ind_soc_config_t soc; 
    
    /** The Indigo Connection Manager configuration data. */
    ind_cxn_config_t cxn; 

    /** The Indigo Port Manager configuration data. */
    ind_port_config_t port; 

    /** The Indigo Forwarding configuration data. */
    ind_fwd_config_t fwd; 

    /** The Indigo Core configuration data. */
    ind_core_config_t core; 

    /** The Indigo Port configuration for added ports. */
    indigo_port_config_t port_add_config; 


    /*************************************************************
     *
     * This example uses veth interfaces. Unless you have
     * modified the permissions, or set the network capabilities
     * permissions, this example should be run under sudo:
     *
     ************************************************************/
#if LRI_CONFIG_ROOT_ACCESS_CHECK == 1
    if(geteuid() != 0) { 
        fprintf(stderr, "Please run this example under sudo.\n"); 
        return 1; 
    }
#endif

     
    /*************************************************************
     *
     * Step 1: 
     * 
     * Initialize configuration data structures. 
     * 
     * These are a sample of the options that can be configured. 
     *
     ************************************************************/
    AIM_ZERO(port); 
    port.of_version = OF_VERSION_1_0; 
    port.max_ports = LRI_MAX_PORTS; 

    AIM_ZERO(fwd); 
    fwd.of_version = OF_VERSION_1_0;
    fwd.max_flows = LRI_MAX_FLOWS; 

    AIM_ZERO(core); 
    core.expire_flows = 1; 
    core.stats_check_ms = 500; 
    core.max_flowtable_entries = LRI_MAX_FLOWS; 
    
    AIM_ZERO(port_add_config); 
    port_add_config.disable_on_add = 0;

    /*************************************************************
     *
     * Step 2: 
     *
     * Initialize Indigo Modules. 
     *
     ************************************************************/
    
    TRY(ind_soc_init(&soc));
    TRY(ind_cxn_init(&cxn));
    TRY(ind_port_init(&port));
    TRY(ind_fwd_init(&fwd));
    TRY(ind_core_init(&core));

    
    /*************************************************************
     *
     * Step 3: 
     *
     * Add port interfaces. 
     *
     * For the purposes of this example, the folling ports are 
     * added:
     * 
     *     veth0
     *     veth2
     *     veth4
     *     veth6
     *
     ************************************************************/
    TRY(indigo_port_interface_add("veth0", 1, &port_add_config));
    TRY(indigo_port_interface_add("veth2", 2, &port_add_config));
    TRY(indigo_port_interface_add("veth4", 3, &port_add_config));
    TRY(indigo_port_interface_add("veth6", 4, &port_add_config));


    /*************************************************************
     *
     * Step 4: 
     *
     * Enable All Modules.
     *
     ************************************************************/
    TRY(ind_soc_enable_set(1));
    TRY(ind_cxn_enable_set(1));
    TRY(ind_fwd_enable_set(1));
    TRY(ind_port_enable_set(1));
    TRY(ind_core_enable_set(1));
    
    /*************************************************************
     *
     * Step 5:
     * 
     * Add a controller. 
     *
     ************************************************************/
    char* caddress = LRI_CONTROLLER_ADDRESS; 
    int cport = LRI_CONTROLLER_PORT; 

    if(argc == 3) { 
        /* take from arguments, no validation */
        caddress = argv[1]; 
        cport = atoi(argv[2]); 
    }
        
    indigo_cxn_info_t cxn0; 
    AIM_ZERO(cxn0);
    cxn0.cxn_config_params.version = OF_VERSION_1_0; 
    cxn0.cxn_proto_params.tcp_over_ipv4.protocol = 
        INDIGO_CXN_PROTO_TCP_OVER_IPV4; 
    
    strcpy(cxn0.cxn_proto_params.tcp_over_ipv4.controller_ip, caddress); 
    cxn0.cxn_proto_params.tcp_over_ipv4.controller_port = cport; 
    cxn0.cxn_config_params.periodic_echo_ms = 10000; 
    cxn0.cxn_config_params.reset_echo_count = 5; 

    TRY(indigo_cxn_connection_add(&cxn0.cxn_proto_params, 
                                  &cxn0.cxn_config_params, 
                                  &cxn0.cxn_id)); 


    
    /*************************************************************
     *
     * Step 6:
     * 
     * Run the Indigo select() loop with no timeout. 
     *
     ************************************************************/
    ind_soc_select_and_run(-1); 


    /*************************************************************
     *
     * Step 7:
     * 
     * Example de-initialization. 
     *
     * You won't get here unless the ind_soc_select_and_run() timeout
     * value is not infinite or an error occured. 
     *
     ************************************************************/
    TRY(ind_core_finish()); 
    TRY(ind_fwd_finish()); 
    TRY(ind_port_finish()); 
    TRY(ind_cxn_finish()); 
    TRY(ind_soc_finish()); 
    
    return 0; 
}

