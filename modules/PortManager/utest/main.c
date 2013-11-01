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
#include <SocketManager/socketmanager.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__APPLE__)
#include <mcheck.h>
#define MCHECK_INIT mcheck(NULL)
#else /* mcheck not available under OS X */
#define MCHECK_INIT do { } while (0)
#endif

#define OK(x) TEST_ASSERT((x) == INDIGO_ERROR_NONE)

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))

#define TEST_IFACE        "udp|send:127.0.0.1:30001"
#define TEST_OF_PORT_NUM  1
#define TEST_PKT_LEN      100

void
assert_fail(unsigned line, char *expr)
{
    printf("Assertion failed, line=%u, expr=\"%s\"\n", line, expr);
}

#define TEST_ASSERT(expr)  do { if (!(expr)) { assert_fail(__LINE__, # expr); } } while (0)

#define TRUE   1
#define FALSE  0
#if 0 /* link conflict with forwarding lib */
indigo_error_t
indigo_fwd_packet_receive(of_port_no_t of_port_num,
                          uint8_t      *data,
                          unsigned     len
                          )
{
    return INDIGO_ERROR_NONE;
}
#endif
indigo_error_t
ind_soc_socket_register(int socket_id,
                        ind_soc_socket_ready_callback_f callback,
                        void *cookie)
{
    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_soc_socket_unregister(int socket_id)
{
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_core_packet_in(of_packet_in_t *packet_in)
{
    return INDIGO_ERROR_NONE;
}

ind_port_config_t ind_port_config[1] = {{
        OF_VERSION_1_0,             /* of_version */
        10                          /* max_ports */
    }};

indigo_port_config_t indigo_port_config[1] = {{
        0                           /* disable_on_add */
    }};


/* Fake notifications to Forwarding */

void
indigo_fwd_pkt_rx(void)
{
}

/* Fake notifcations to Core */

of_port_status_t *saved_of_port_status;

void
indigo_core_port_status_update(of_port_status_t *of_port_status)
{
    saved_of_port_status = of_port_status;
}

void
port_status_arm(void)
{
    saved_of_port_status = 0;
}

void
port_status_chk(of_port_no_t of_port_num, unsigned reason)
{
    of_port_desc_t *saved_of_port_desc = 0;
    uint8_t        saved_reason;
    of_port_no_t   saved_of_port_num;

    TEST_ASSERT(saved_of_port_status);
    saved_of_port_desc = of_port_status_desc_get(saved_of_port_status);
    TEST_ASSERT(saved_of_port_desc != NULL);

    of_port_desc_port_no_get(saved_of_port_desc, &saved_of_port_num);
    TEST_ASSERT(of_port_num == saved_of_port_num);
    of_port_status_reason_get(saved_of_port_status, &saved_reason);
    TEST_ASSERT(reason == saved_reason);
  
    of_port_desc_delete(saved_of_port_desc);
    of_port_status_delete(saved_of_port_status);
    saved_of_port_status = 0;
}

indigo_error_t
indigo_core_dpid_set(of_dpid_t dpid)
{
    AIM_REFERENCE(dpid);
    return INDIGO_ERROR_NONE;
}

int
main(int argc, char* argv[])
{
    indigo_error_t rv;

    // MCHECK_INIT;  /* @fixme */

    /* Init module */
    TEST_ASSERT(INDIGO_SUCCESS(ind_port_init(ind_port_config)));


    /* Get port features */
    {
        of_features_reply_t *of_features_reply = 0;
        of_list_port_desc_t *of_list_port_desc = 0;
        of_port_desc_t      of_port_desc[1];
        unsigned            n;
        int                 rv;

        of_features_reply = of_features_reply_new(ind_port_config->of_version);
        TEST_ASSERT(of_features_reply != NULL);

        TEST_ASSERT(INDIGO_SUCCESS(indigo_port_features_get(of_features_reply)));

        /* Features should have no ports in list */
        of_list_port_desc = of_features_reply_ports_get(of_features_reply);
        TEST_ASSERT(of_list_port_desc != NULL);
        n = 0;
        OF_LIST_PORT_DESC_ITER(of_list_port_desc, of_port_desc, rv) {
            ++n;
        }
        TEST_ASSERT(rv == OF_ERROR_RANGE);
        TEST_ASSERT(n == 0);
        of_list_port_desc_delete(of_list_port_desc);

        of_features_reply_delete(of_features_reply);
    }

    /* Add a port */
    {
        port_status_arm();

        TEST_ASSERT(INDIGO_SUCCESS(indigo_port_interface_add(TEST_IFACE, TEST_OF_PORT_NUM, indigo_port_config)));

        /* Check that "port add" notification was received */
        port_status_chk(1, OF_PORT_CHANGE_REASON_ADD);
    }

    /* Set/get the port mac addr */
    {
        of_mac_addr_t mac = {{0, 1, 2, 3, 4, 5}};
        of_mac_addr_t mac_in;

        TEST_ASSERT(ind_port_mac_addr_set(TEST_OF_PORT_NUM, &mac) ==
                    INDIGO_ERROR_NONE);
        TEST_ASSERT(ind_port_mac_addr_get(TEST_OF_PORT_NUM, &mac_in) ==
                    INDIGO_ERROR_NONE);
        TEST_ASSERT(memcmp(&mac, &mac_in, sizeof(mac_in)) == 0);
        TEST_ASSERT(ind_port_base_mac_addr_set(&mac) == INDIGO_ERROR_NONE);
        TEST_ASSERT(ind_port_mac_addr_get(TEST_OF_PORT_NUM, &mac_in) ==
                    INDIGO_ERROR_NONE);
        TEST_ASSERT(memcmp(&mac, &mac_in, sizeof(mac_in)) == 0);
    }
  
    /* Get port features again */
    {
        of_features_reply_t *of_features_reply = 0;
        of_list_port_desc_t *of_list_port_desc;
        of_port_desc_t      of_port_desc[1];
        unsigned            n;
        int                 rv;
        of_mac_addr_t mac_exp = {{0, 1, 2, 3, 4, 5}};
        of_mac_addr_t mac_in;

        of_features_reply = of_features_reply_new(ind_port_config->of_version);
        TEST_ASSERT(of_features_reply != NULL);

        TEST_ASSERT(INDIGO_SUCCESS(indigo_port_features_get(of_features_reply)));

        /* Features should have 1 port in list */
        of_list_port_desc = of_features_reply_ports_get(of_features_reply);
        TEST_ASSERT(of_list_port_desc != NULL);

        n = 0;
        OF_LIST_PORT_DESC_ITER(of_list_port_desc, of_port_desc, rv) {
            of_port_no_t of_port_num;
            
            of_port_desc_port_no_get(of_port_desc, &of_port_num);
            TEST_ASSERT(of_port_num == TEST_OF_PORT_NUM);

            of_port_desc_hw_addr_get(of_port_desc, &mac_in);
            TEST_ASSERT(memcmp(&mac_in, &mac_exp, sizeof(mac_in)) == 0);
            ++n;
        }
        TEST_ASSERT(rv == OF_ERROR_RANGE);
        TEST_ASSERT(n == 1);
        of_list_port_desc_delete(of_list_port_desc);

        of_features_reply_delete(of_features_reply);
    }

    /* Send a packet out the port */
    {
        uint8_t  buf[TEST_PKT_LEN];
        unsigned i;          

        /* Completely bogus packet data... */
        for (i = 0; i < ARRAY_SIZE(buf); ++i)  buf[i] = i;

        TEST_ASSERT(INDIGO_SUCCESS(indigo_port_packet_emit(TEST_OF_PORT_NUM, 0, buf, sizeof(buf))));

        /** \todo Verify packet transmission, using loopback, or tcpdump,
            or...? */
    }

    /* Get port's statistics */
    {
        of_port_stats_request_t      *request = 0;
        of_port_stats_reply_t        *reply = 0;

        request = of_port_stats_request_new(ind_port_config->of_version);
        TEST_ASSERT(request != NULL);
        of_port_stats_request_port_no_set(request, OF_PORT_DEST_ALL);

        rv = indigo_port_stats_get(request, &reply);
        TEST_ASSERT(rv == INDIGO_ERROR_NONE);

        {
            of_list_port_stats_entry_t   list;
            of_port_stats_entry_t        entry;
            int rv;
            int n;

            of_port_stats_reply_entries_bind(reply, &list);
            n = 0;
            OF_LIST_PORT_STATS_ENTRY_ITER(&list, &entry, rv) {
                of_port_no_t of_port_num;
                uint64_t     stat;

                of_port_stats_entry_port_no_get(&entry, &of_port_num);
                TEST_ASSERT(of_port_num == TEST_OF_PORT_NUM);
                of_port_stats_entry_tx_packets_get(&entry, &stat);
                TEST_ASSERT(stat == 1);
                of_port_stats_entry_tx_bytes_get(&entry, &stat);
                TEST_ASSERT(stat == TEST_PKT_LEN);

                ++n;
            }
            TEST_ASSERT(rv == OF_ERROR_RANGE);
            TEST_ASSERT(n == 1);
        }

        of_port_stats_request_delete(request);
        of_port_stats_reply_delete(reply);
    }

    /* Get queue statistics */
    {
        of_queue_stats_request_t      *request = 0;
        of_queue_stats_reply_t        *reply = 0;

        request = of_queue_stats_request_new(ind_port_config->of_version);
        TEST_ASSERT(request != NULL);
        of_queue_stats_request_port_no_set(request, OF_PORT_DEST_ALL);

        of_queue_stats_request_queue_id_set(request, OF_QUEUE_ALL);

        rv = indigo_port_queue_stats_get(request, &reply);
        TEST_ASSERT(rv == INDIGO_ERROR_NONE);

        {
            of_list_queue_stats_entry_t   list;
            of_queue_stats_entry_t        entry;
            int                           rv;
            unsigned                      n;

            of_queue_stats_reply_entries_bind(reply, &list);
            n = 0;
            OF_LIST_QUEUE_STATS_ENTRY_ITER(&list, &entry, rv) {
                of_port_no_t of_port_num;
                uint32_t     queue_id;
                uint64_t     stat;

                of_queue_stats_entry_port_no_get(&entry, &of_port_num);
                TEST_ASSERT(of_port_num == TEST_OF_PORT_NUM);
                of_queue_stats_entry_queue_id_get(&entry, &queue_id);
                TEST_ASSERT(queue_id == 0);
                of_queue_stats_entry_tx_packets_get(&entry, &stat);
                TEST_ASSERT(stat == 1);
                of_queue_stats_entry_tx_bytes_get(&entry, &stat);
                TEST_ASSERT(stat == TEST_PKT_LEN);

                ++n;
            }
            TEST_ASSERT(rv == OF_ERROR_RANGE);
            TEST_ASSERT(n == 1);
        }

        of_queue_stats_request_delete(request);
        of_queue_stats_reply_delete(reply);
    }

    /* Modify port's configuration */
    {
        of_port_mod_t              *mod_req = 0;

        mod_req = of_port_mod_new(ind_port_config->of_version);
        TEST_ASSERT(mod_req != NULL);
        of_port_mod_port_no_set(mod_req, TEST_OF_PORT_NUM);
        of_port_mod_config_set(mod_req, 0x12345678);

        rv = indigo_port_modify(mod_req);
        TEST_ASSERT(rv == INDIGO_ERROR_NONE);

        of_port_mod_delete(mod_req);
    }

    /* Delete the port */
    {
        port_status_arm();

        TEST_ASSERT(indigo_port_interface_remove(TEST_IFACE) == INDIGO_ERROR_NONE);

        /* Check that "port deleted" notification was received" */
        port_status_chk(1, OF_PORT_CHANGE_REASON_DELETE);
    }

    /* Shut down module */
    TEST_ASSERT(ind_port_finish() == INDIGO_ERROR_NONE);
  
    return (0);
}
