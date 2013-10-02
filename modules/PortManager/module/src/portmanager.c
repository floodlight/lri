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

/**
 * @file
 * @brief Implementation of Port Manager for Indigo Linux Ref
 */

#include "portmanager_log.h"
#include "portmanager_int.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <VPI/vpi.h>

#include <indigo/memory.h>
#include <PortManager/portmanager.h>
#include <PortManager/portmanager_porting.h>
#include <SocketManager/socketmanager.h>
#include <Forwarding/forwarding.h>
#include <cjson/cJSON.h>
#include <Configuration/configuration.h>

static const char __file__[] = "$Id$";

static int init_done = 0;

#define LOXI_SUCCESS(x)  ((x) == OF_ERROR_NONE)
#define LOXI_FAILURE(x)  (!LOXI_SUCCESS(x))

/* Short hand logging macros */
#define LOG_ERROR AIM_LOG_ERROR
#define LOG_WARN AIM_LOG_WARN 
#define LOG_INFO AIM_LOG_INFO
#define LOG_VERBOSE AIM_LOG_VERBOSE
#define LOG_TRACE AIM_LOG_TRACE

static int module_enabled = 0; /**< Module enable state */

#define MAX_PKT_LEN   16384     /**< Maximum packet length */

static ind_port_config_t my_config[1];

/** \brief Per-port data */
struct of_port {
    char     ifname[128];      /**< Name of port's VPI or Linux network interface */
    of_mac_addr_t mac;

    vpi_t    vpi;              /**< VPI handle; NULL = not in use */
    uint32_t config;            /**< OpenFlow's port config,
                                   from of_port_mod */
    uint64_t cnt_tx_pkts;       /**< Transmitted packets counter */
    uint64_t cnt_tx_bytes;      /**< Transmitted bytes counter */
    uint64_t cnt_rx_pkts;       /**< Received packets counter */
    uint64_t cnt_rx_bytes;      /**< Received bytes counter */
};

static struct of_port *of_port_tbl;  /**< Table of all ports */

/** \brief Check if a port number is valid

\note OF spec specifies that port numbers start at 1.
*/

static unsigned
of_port_num_valid(of_port_no_t of_port_num)
{
    return (of_port_num >= 1 && of_port_num <= my_config->max_ports);
}


/** \brief Return pointer to port structure for given port number */

static struct of_port *
of_port_num_to_ptr(of_port_no_t of_port_num)
{
    return (&of_port_tbl[of_port_num - 1]);
}


/** \brief Initialize port table */

static indigo_error_t
of_port_tbl_init(void)
{
    unsigned       n;
    struct of_port *p;

    if ((of_port_tbl = (struct of_port *)
         INDIGO_MEM_ALLOC(my_config->max_ports * sizeof(struct of_port))) == 0
        ) {
        LOG_ERROR("No memory");
        return (INDIGO_ERROR_UNKNOWN);
    }

    for (p = of_port_tbl, n = my_config->max_ports; n; --n, ++p) {
        p->vpi = NULL; /* Mark all port slots as not in use */
    }

    return (INDIGO_ERROR_NONE);
}


/** \brief Destroy port table */

static void
of_port_tbl_delete(void)
{
    INDIGO_MEM_FREE(of_port_tbl);
}


/** \brief Check if a port is in use */

static int
of_port_inuse(struct of_port *p)
{
    return p->vpi != NULL;
}

static int
of_port_no_flood(struct of_port *p)
{
    return (p->config & OF_PORT_CONFIG_FLAG_NO_FLOOD);
}


/** \brief Return a pollable file descriptor */

static int
of_port_fd(struct of_port *p)
{
    return vpi_descriptor_get(p->vpi);
}


/** \brief Set of port stats */

struct of_port_stats {
    uint64_t rx_packets;     /**< Number of received packets. */
    uint64_t tx_packets;     /**< Number of transmitted packets. */
    uint64_t rx_bytes;       /**< Number of received bytes. */
    uint64_t tx_bytes;       /**< Number of transmitted bytes. */
    uint64_t rx_dropped;     /**< Number of packets dropped by RX. */
    uint64_t tx_dropped;     /**< Number of packets dropped by TX. */
    uint64_t rx_errors;      /**< Number of receive errors.  This is a
                                super-set of more specific receive errors and
                                should be greater than or equal to the sum of
                                all rx_*_err values. */
    uint64_t tx_errors;      /**< Number of transmit errors.  This is a
                                super-set of more specific transmit errors and
                                should be greater than or equal to the sum of
                                all tx_*_err values (none currently defined.)
                             */  
    uint64_t rx_frame_err;   /**< Number of frame alignment errors. */
    uint64_t rx_over_err;    /**< Number of packets with RX overrun. */
    uint64_t rx_crc_err;     /**< Number of CRC errors. */
    uint64_t collisions;     /**< Number of collisions. */
};


/** \brief Get port stats */

static indigo_error_t
port_stats_get(of_port_no_t of_port_num, struct of_port_stats *port_stats)
{
    struct of_port *p;

    INDIGO_MEM_SET(port_stats, 0, sizeof(*port_stats));

    if (of_port_num == OF_PORT_DEST_CONTROLLER) {
        /* This is a bit confusing.  Packet-ins are packets received
         * on other ports and forwarded to the controller.  Since they
         * go out _to_ the controller, they are actually TX packets for
         * the controller port.  Vice versa for packet-outs which count
         * as RX packets.
         */
        port_stats->rx_packets = ind_fwd_packet_out_packets;
        port_stats->rx_bytes   = ind_fwd_packet_out_bytes;

        port_stats->tx_packets = ind_fwd_packet_in_packets;
        port_stats->tx_bytes   = ind_fwd_packet_in_bytes;
    } else if (of_port_num_valid(of_port_num)) {
        p = of_port_num_to_ptr(of_port_num);

        /** \todo Get proper stats from interface */

        port_stats->rx_packets = p->cnt_rx_pkts;
        port_stats->tx_packets = p->cnt_tx_pkts;
        port_stats->rx_bytes   = p->cnt_rx_bytes;
        port_stats->tx_bytes   = p->cnt_tx_bytes;
    } else {
        return INDIGO_ERROR_NOT_FOUND;
    }

    return (INDIGO_ERROR_NONE);
}


/** \brief Add statistics for a port to a LOXI port stats list */

static indigo_error_t
port_stats_add(of_list_port_stats_entry_t *port_stats_list,
               of_port_no_t               of_port_num
               )
{
    indigo_error_t        result = INDIGO_ERROR_NONE;
    struct of_port_stats  port_stats[1];
    of_port_stats_entry_t *of_port_stats_entry = 0;

    if (INDIGO_FAILURE(result = port_stats_get(of_port_num, port_stats))) {
        LOG_ERROR("port_stats_get(of_port_num=%u) failed", of_port_num);
        return (result);
    }

    of_port_stats_entry = of_port_stats_entry_new(port_stats_list->version);
    if (of_port_stats_entry == NULL) {
        LOG_ERROR("of_port_stats_entry_new() failed");
        return (INDIGO_ERROR_UNKNOWN);
    }

    of_port_stats_entry_port_no_set(of_port_stats_entry, of_port_num);
    of_port_stats_entry_rx_packets_set(of_port_stats_entry, port_stats->rx_packets);
    of_port_stats_entry_tx_packets_set(of_port_stats_entry, port_stats->tx_packets);
    of_port_stats_entry_rx_bytes_set(of_port_stats_entry, port_stats->rx_bytes);
    of_port_stats_entry_tx_bytes_set(of_port_stats_entry, port_stats->tx_bytes);
    of_port_stats_entry_rx_dropped_set(of_port_stats_entry, port_stats->rx_dropped);
    of_port_stats_entry_tx_dropped_set(of_port_stats_entry, port_stats->tx_dropped);
    of_port_stats_entry_rx_errors_set(of_port_stats_entry, port_stats->rx_errors);
    of_port_stats_entry_tx_errors_set(of_port_stats_entry, port_stats->tx_errors);
    of_port_stats_entry_rx_frame_err_set(of_port_stats_entry, port_stats->rx_frame_err);
    of_port_stats_entry_rx_over_err_set(of_port_stats_entry, port_stats->rx_over_err);
    of_port_stats_entry_rx_crc_err_set(of_port_stats_entry, port_stats->rx_crc_err);
    of_port_stats_entry_collisions_set(of_port_stats_entry, port_stats->collisions);

    if (LOXI_FAILURE(of_list_port_stats_entry_append(
                                                     port_stats_list,
                                                     of_port_stats_entry
                                                     )
                     )
        ) {
        LOG_ERROR("of_list_port_stats_entry_append() failed");
        result = INDIGO_ERROR_UNKNOWN;
    }

    of_port_stats_entry_delete(of_port_stats_entry);
  
    return (result);
}


/** \brief Add statistics for a queue to a queue stats list */

static indigo_error_t
queue_stats_add(of_list_queue_stats_entry_t *queue_stats_list,
                of_port_no_t                of_port_num,
                unsigned                    queue_id
                )
{
    indigo_error_t         result = INDIGO_ERROR_NONE;
    struct of_port_stats   port_stats[1];
    of_queue_stats_entry_t *of_queue_stats_entry = NULL;

    if (queue_id != 0) {
        LOG_ERROR("Queue id %u out of range", queue_id);
        result = INDIGO_ERROR_PARAM;
        goto done;
    }

    if (INDIGO_FAILURE(result = port_stats_get(of_port_num, port_stats))) {
        LOG_ERROR("port_stats_get(of_port_num=%u) failed",
                         of_port_num
                         );
        goto done;
    }

    of_queue_stats_entry =
        of_queue_stats_entry_new(queue_stats_list->version);
    if (of_queue_stats_entry == NULL) {
        LOG_ERROR("of_queue_stats_entry_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_queue_stats_entry_port_no_set(of_queue_stats_entry, of_port_num);
    of_queue_stats_entry_queue_id_set(of_queue_stats_entry, queue_id);
    of_queue_stats_entry_tx_bytes_set(of_queue_stats_entry, port_stats->tx_bytes);
    of_queue_stats_entry_tx_packets_set(of_queue_stats_entry, port_stats->tx_packets);
    of_queue_stats_entry_tx_errors_set(of_queue_stats_entry, 0);

    if (LOXI_FAILURE(of_list_queue_stats_entry_append(queue_stats_list,
                                                      of_queue_stats_entry
                                                      )
                     )
        ) {
        LOG_ERROR("of_list_queue_stats_entry_append() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (of_queue_stats_entry != NULL) {
        of_queue_stats_entry_delete(of_queue_stats_entry);
    }

    return (result);
}


/** \brief Set of port status items */

struct port_status {
    unsigned linkup;              /**< TRUE <=> Link is up */
};


/** \brief Get status of a port */

static indigo_error_t
port_status_get(of_port_no_t of_port_num, struct port_status *port_status)
{
    INDIGO_MEM_SET(port_status, 0, sizeof(*port_status));

    /** \todo Get proper status of Linux network interface;
     */

    port_status->linkup = 1;      /* Assume link is up */

    return (INDIGO_ERROR_NONE);
}


/** \brief Fill in LOXI of_port_desc for given port */

static indigo_error_t
port_desc_set(of_port_desc_t *of_port_desc, of_port_no_t of_port_num)
{
    indigo_error_t     result = INDIGO_ERROR_NONE;
    struct of_port     *p;
    struct port_status port_status[1];
    uint32_t           of_port_state;

    if (INDIGO_FAILURE(result = port_status_get(of_port_num, port_status))) {
        LOG_ERROR("port_status_get(of_port_num=%u) failed", of_port_num);
        return (result);
    }
  
    of_port_state = 0;
    if (!port_status->linkup) {
        OF_PORT_STATE_FLAG_LINK_DOWN_SET(of_port_state, of_port_desc->version);
    }

    p = of_port_num_to_ptr(of_port_num);

    of_port_desc_port_no_set(of_port_desc, of_port_num);
    of_port_desc_hw_addr_set(of_port_desc, p->mac);

    of_port_desc_name_set(of_port_desc, p->ifname);
    of_port_desc_config_set(of_port_desc, p->config);
    of_port_desc_state_set(of_port_desc, of_port_state);

    /** \todo Get proper current, advertised supported and peer values;
     */

    of_port_desc_curr_set(of_port_desc, 0);
    of_port_desc_advertised_set(of_port_desc, 0);
    of_port_desc_supported_set(of_port_desc, 0);
    of_port_desc_peer_set(of_port_desc, 0);

    return (INDIGO_ERROR_NONE);
}


/** \brief Compose LOXI object for port status change, and send to peer */

static indigo_error_t
port_status_notify(of_port_no_t of_port_num, unsigned reason)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    of_port_desc_t   *of_port_desc   = 0;
    of_port_status_t *of_port_status = 0;

    /* Don't know the cxn this is going to, so use configured version */
    if ((of_port_desc = of_port_desc_new(my_config->of_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((result = port_desc_set(of_port_desc, of_port_num))
        != INDIGO_ERROR_NONE
        ) {
        LOG_ERROR("port_desc_set() failed");
        goto done;
    }

    if ((of_port_status = of_port_status_new(my_config->of_version)) == 0) {
        LOG_ERROR("of_port_status_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    
    of_port_status_reason_set(of_port_status, reason);
    of_port_status_desc_set(of_port_status, of_port_desc);
    of_port_desc_delete(of_port_desc);
    
    indigo_core_port_status_update(of_port_status);
    
    of_port_desc = 0;       /* Deleted above */
    of_port_status = 0;     /* No longer owned */

 done:
    if (of_port_desc)    of_port_desc_delete(of_port_desc);
    if (of_port_status)  of_port_status_delete(of_port_status);
    
    return (result);
}


/** \brief Process packet received on socket */

void pkt_rx(int fd,
            void *cookie,
            int read_ready,
            int write_ready,
            int error_seen)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct of_port *p;
    of_port_no_t   of_port_num;
    unsigned char  buf[MAX_PKT_LEN];

    /* Ignore some params */
    (void)cookie;
    (void)write_ready;
    (void)error_seen;

    /* Find corresponding OF port */

    LOG_TRACE("Packet RX for %d", fd);

    for (p = of_port_tbl, of_port_num = 1;
         of_port_num <= my_config->max_ports;
         ++of_port_num, ++p
         ) {
        if (fd == of_port_fd(p)) {
            int len;
      
            /* Get packet data */
            LOG_TRACE("Reading for port %s", p->ifname);

            if ((len = vpi_recv(p->vpi, buf, sizeof(buf), 0)) < 0) {
                LOG_ERROR("vpi_recv() failed");
                return;
            }
            
            if(len == 0) {
                /* No packet */
                return; 
            }

            LOG_TRACE("Read %d bytes for port %s", len, p->ifname);

            if (!OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(p->config, 
                                                    my_config->of_version)
                && !OF_PORT_CONFIG_FLAG_NO_RECV_TEST(p->config, 
                                                     my_config->of_version)
                ) {
                /* Port is enabled and port receive is enabled */

                /* Update port stats */

                ++p->cnt_rx_pkts;
                p->cnt_rx_bytes += (unsigned) len;
        
                /* Run packet through forwarding */
                result = indigo_fwd_packet_receive(of_port_num, buf, len);
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("indigo_fwd_pkt_rx() failed");
                }
            }

            return;
        }
    }

    LOG_ERROR("Socket not found");
    return;
}

/***************************************************************************/

/** \brief Fill in port features in LOXI switch features object */

indigo_error_t
indigo_port_features_get(of_features_reply_t *features)
{
    indigo_error_t      result             = INDIGO_ERROR_NONE;
    of_list_port_desc_t *of_list_port_desc = 0;
    of_port_desc_t      *of_port_desc      = 0;
    struct of_port      *p;
    of_port_no_t        of_port_num;

    if ((of_port_desc = of_port_desc_new(my_config->of_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_port_desc = of_list_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_list_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    /* Add all ports to list of ports in LOXI object */

    for (p = of_port_tbl, of_port_num = 1;
         of_port_num <= my_config->max_ports;
         ++of_port_num, ++p
         ) {
        if (!of_port_inuse(p))  continue;

        if (INDIGO_FAILURE(result = port_desc_set(of_port_desc, of_port_num))) {
            LOG_ERROR("port_desc_set(of_port_num=%u) failed", of_port_num);
            goto done;
        }

        if (LOXI_FAILURE(of_list_port_desc_append(of_list_port_desc,
                                                  of_port_desc
                                                  )
                         )
            ) {
            LOG_ERROR("of_list_port_desc_append() failed");
            result = INDIGO_ERROR_UNKNOWN;
            goto done;
        }
    }

    if (of_features_reply_ports_set(features, of_list_port_desc) < 0) {
        result = INDIGO_ERROR_UNKNOWN;
    }

 done:
    if (of_list_port_desc)  of_list_port_desc_delete(of_list_port_desc);
    if (of_port_desc)       of_port_desc_delete(of_port_desc);

    return (result);
}


/** \brief Modify an OF port's configuration */


void
indigo_port_modify(of_port_mod_t *port_mod,
                   indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    of_port_no_t   of_port_num;
    uint32_t       config, mask;
    struct of_port *p;

    of_port_mod_port_no_get(port_mod, &of_port_num);

    if (!of_port_num_valid(of_port_num)) {
        LOG_ERROR("Port number out of range");
        result = INDIGO_ERROR_PARAM;
        goto done;
    }

    if (!of_port_inuse(p = of_port_num_to_ptr(of_port_num))) {
        LOG_ERROR("Port not in use");
        result = INDIGO_ERROR_NOT_FOUND;
        goto done;
    }

    of_port_mod_config_get(port_mod, &config);
    of_port_mod_mask_get(port_mod, &mask);

    p->config = (config & mask) | (p->config & ~mask);

 done:
    indigo_core_port_modify_callback(result, callback_cookie);
}


/** \brief Get statistics for requested OF ports */

void
indigo_port_stats_get(of_port_stats_request_t *port_stats_request,
                      indigo_cookie_t callback_cookie)
{
    indigo_error_t             result = INDIGO_ERROR_NONE;
    of_list_port_stats_entry_t *port_stats_list = 0;
    of_port_no_t               req_of_port_num, of_port_num;
    struct of_port             *p;
    of_port_stats_reply_t      *port_stats_reply;
    of_version_t               version;

    version = port_stats_request->version;
    port_stats_reply = of_port_stats_reply_new(version);
    if (port_stats_reply == NULL) {
        LOG_ERROR("port_stats_reply_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_port_stats_request_port_no_get(port_stats_request, &req_of_port_num);

    port_stats_list = of_list_port_stats_entry_new(version);
    if (port_stats_list == 0) {
        AIM_LOG_ERROR("of_list_port_stats_entry_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if (req_of_port_num == OF_PORT_DEST_ALL_BY_VERSION(version) ||
        req_of_port_num == OF_PORT_DEST_NONE_BY_VERSION(version)) {
        /** @fixme: Need to handle OF_PORT_DEST_CONTROLLER? */
        for (p = of_port_tbl, of_port_num = 1;
             of_port_num <= my_config->max_ports;
             ++of_port_num, ++p
             ) {
            if (!of_port_inuse(p))  continue;

            result = port_stats_add(port_stats_list, of_port_num);
            if (INDIGO_FAILURE(result)) {
                LOG_ERROR("port_stats_add() failed");
                goto done;
            }
        }
    } else {
        result = port_stats_add(port_stats_list, req_of_port_num);
        if (INDIGO_FAILURE(result)) {
            LOG_ERROR("port_stats_add() failed");
            goto done;
        }
    }

    result = of_port_stats_reply_entries_set(port_stats_reply, port_stats_list);
    if (result < 0) {
        LOG_ERROR("port_stats_reply_entries_set() failed");
        goto done;
    }

 done:
    if (port_stats_list) {
        of_list_port_stats_entry_delete(port_stats_list);
    }

    indigo_core_port_stats_get_callback(result, port_stats_reply,
                                        callback_cookie);
}


/** \brief Return the configuration of port transmit queue(s) */


void
indigo_port_queue_config_get(of_queue_get_config_request_t *request,
                             indigo_cookie_t callback_cookie)
{
    /* @fixme Stubbed out for now */
    of_queue_get_config_reply_t *reply;
    indigo_error_t result = INDIGO_ERROR_NONE;
    uint32_t xid;

    reply = of_queue_get_config_reply_new(request->version);
    if (reply == NULL) {
        result = INDIGO_ERROR_RESOURCE;
        LOG_ERROR("Could not allocate queue config reply");
    } else {
        of_queue_get_config_request_xid_get(request, &xid);
        of_queue_get_config_reply_xid_set(reply, xid);
    }

    /* @FIXME */
    LOG_WARN("Queue config get not implemented");

    indigo_core_queue_config_get_callback(result, reply, callback_cookie);
}


/** \brief Return the statistics for port transmit queue(s) */

void
indigo_port_queue_stats_get(of_queue_stats_request_t *request,
                            indigo_cookie_t callback_cookie)
{
    indigo_error_t              result = INDIGO_ERROR_NONE;
    of_port_no_t                req_of_port_num, of_port_num;
    uint32_t                    queue_id;
    struct of_port              *p;
    of_list_queue_stats_entry_t *entry = NULL;
    of_queue_stats_reply_t      *reply;
    uint32_t xid;

    reply = of_queue_stats_reply_new(request->version);
    if (reply == NULL) {
        LOG_ERROR("of_queue_stats_reply_new() failed");
        result = INDIGO_ERROR_RESOURCE;
        goto done;
    }

    of_queue_stats_request_xid_get(request, &xid);
    of_queue_stats_reply_xid_set(reply, xid);
    of_queue_stats_request_port_no_get(request, &req_of_port_num);
    of_queue_stats_request_queue_id_get(request, &queue_id);

    entry = of_list_queue_stats_entry_new(request->version);
    if (entry == NULL) {
        LOG_ERROR("of_list_queue_stats_entry_new() failed");
        result = INDIGO_ERROR_RESOURCE;
        goto done;
    }

    if ((req_of_port_num != OF_PORT_DEST_ALL) &&
            (req_of_port_num != OF_PORT_DEST_CONTROLLER)) {
        if (!of_port_num_valid(req_of_port_num)) {
            LOG_ERROR("Port number out of range");
            result = INDIGO_ERROR_PARAM;
            goto done;
        }
        if (!of_port_inuse(p = of_port_num_to_ptr(req_of_port_num))) {
            LOG_ERROR("Port not in use");
            result = INDIGO_ERROR_PARAM;
            goto done;
        }
    }
  
#define OFPQ_ALL (~0)           /** \todo Remove this, belongs in LOXI */

    if (queue_id != OFPQ_ALL && queue_id != 0) {
        LOG_ERROR("Queue id out of range");
        result = INDIGO_ERROR_PARAM;
        goto done;
    }

    if (req_of_port_num == OF_PORT_DEST_ALL) {
        /* @todo Clarify the logic below; what is test for port active? */
        for (p = of_port_tbl, of_port_num = 1;
             of_port_num <= my_config->max_ports;
             ++of_port_num, ++p
             ) {
            if (!of_port_inuse(p))  continue;

            result = queue_stats_add(entry, of_port_num, 0);
            if (INDIGO_FAILURE(result)) {
                LOG_ERROR("port_stats_add() failed");
                goto done;
            }
        }
    } else {
        result = queue_stats_add(entry, req_of_port_num, 0);
        if (INDIGO_FAILURE(result)) {
            LOG_ERROR("port_stats_add() failed");
            goto done;
        }
    }

    if (LOXI_FAILURE(of_queue_stats_reply_entries_set(reply, entry))) {
        LOG_ERROR("of_queue_stats_reply_entries_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (entry != NULL) {
        of_list_queue_stats_entry_delete(entry);
    }

    indigo_core_queue_stats_get_callback(result, reply, callback_cookie);
}

/***************************************************************************/

/** \brief Add the given Linux network interface as the given OF port number */

indigo_error_t
indigo_port_interface_add(indigo_port_name_t   ifname,
                          of_port_no_t         of_port_num,
                          indigo_port_config_t *config
                          )
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct of_port *p;
    vpi_t vpi = NULL;
    int fd;
    char vpi_spec[1024];

    LOG_INFO("Adding interface %s as port %d", ifname, of_port_num);

    if (!of_port_num_valid(of_port_num)) {
        LOG_ERROR("Invalid OF port number");
        return (INDIGO_ERROR_PARAM);
    }

    if (of_port_inuse(p = of_port_num_to_ptr(of_port_num))) {
        LOG_ERROR("OF port number in use");
        return (INDIGO_ERROR_EXISTS);
    }

    /*
     * Assume ifname refers to a network adapter unless it has a pipe character
     * in it.
     */
    if (strchr(ifname, '|') == NULL) {
        snprintf(vpi_spec, sizeof(vpi_spec), "pcap|%s", ifname);
    } else {
        strncpy(vpi_spec, ifname, sizeof(vpi_spec));
    }

    vpi = vpi_create(vpi_spec);
    if (vpi == NULL) {
        LOG_ERROR("vpi_create() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

#if PORTMANAGER_CONFIG_INCLUDE_VPI_PCAPDUMP == 1
    {
        snprintf(vpi_spec, sizeof(vpi_spec), "pcapdump|lri-port%.2d.pcap|mpls|PORT%d", 
                 of_port_num, of_port_num); 
        vpi_add_sendrecv_listener_spec(vpi, vpi_spec);
    }
#endif /* PORTMANAGER_CONFIG_INCLUDE_VPI_PCAPDUMP */


    INDIGO_MEM_SET(p, 0, sizeof(*p));
    strncpy(p->ifname, ifname, sizeof(p->ifname) - 1);
    p->ifname[sizeof(p->ifname) - 1] = 0;
    p->vpi = vpi;
    if (config->disable_on_add) {
        /* Port added as disabled */
        LOG_VERBOSE("Disabling port %d due to config", of_port_num);
        OF_PORT_CONFIG_FLAG_PORT_DOWN_SET(p->config, my_config->of_version);
    }

    if ((fd = of_port_fd(p)) == -1) {
        LOG_ERROR("of_port_fd() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    /* Ask sockman to call our receive function when a packet is received
       on port's socket
    */
    ind_soc_socket_register(fd, pkt_rx, INDIGO_COOKIE_NULL);

    /* Notify core of port addition */
    if (INDIGO_FAILURE(result = port_status_notify(of_port_num,
                                                   OF_PORT_CHANGE_REASON_ADD
                                                   )
                       )
        ) {
        LOG_ERROR("port_status_notify() failed");
        goto done;
    }

 done:
    if (INDIGO_FAILURE(result)) {
        if (vpi != NULL) {
            vpi_destroy(vpi);
            p->vpi = NULL;
        }
    }

    return (result);
}

/** \brief Stop using the given Linux network interface as an OF port */

indigo_error_t
indigo_port_interface_remove(indigo_port_name_t ifname)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct of_port *p;
    of_port_no_t   of_port_num;

    LOG_INFO("Removing interface %s", ifname);

    for (p = of_port_tbl, of_port_num = 1;
         of_port_num <= my_config->max_ports;
         ++of_port_num, ++p
         ) {
        if (strcmp(ifname, p->ifname) == 0)  break;
    }

    if (of_port_num > my_config->max_ports) {
        LOG_ERROR("Invalid OF port number");
        return (INDIGO_ERROR_NOT_FOUND);
    }

    if (!of_port_inuse(p)) {
        LOG_ERROR("OF port not in use");
        return (INDIGO_ERROR_UNKNOWN);
    }

    /* Notify core of port deletion */
    result = port_status_notify(of_port_num, OF_PORT_CHANGE_REASON_DELETE);
    if (INDIGO_FAILURE(result)) {
        LOG_ERROR("port_status_notify() failed");
        return (result);
    }

    ind_soc_socket_unregister(of_port_fd(p));
    vpi_destroy(p->vpi);

    p->ifname[0] = 0;
    p->vpi = NULL;
    
    return (INDIGO_ERROR_NONE);
}



indigo_error_t
indigo_port_interface_list(indigo_port_info_t** list)
{
    indigo_port_info_t* head = NULL; 
    struct of_port *p; 
    of_port_no_t of_port_num; 
    
    if(list == NULL) { 
        return INDIGO_ERROR_PARAM; 
    }
    for(of_port_num = my_config->max_ports; of_port_num >= 1; of_port_num--) { 
        p = of_port_tbl + of_port_num - 1; 
        if(of_port_inuse(p)) { 
            indigo_port_info_t* entry = INDIGO_MEM_ALLOC(sizeof(*entry)); 
            strncpy(entry->port_name, p->ifname, sizeof(entry->port_name) - 1);
            entry->of_port = of_port_num;
            entry->next = head; 
            head = entry; 
        }
    }
    *list = head; 
    return INDIGO_ERROR_NONE; 
}


void
indigo_port_interface_list_destroy(indigo_port_info_t* list)
{
    indigo_port_info_t* e = list; 
    while(e) { 
        indigo_port_info_t* link = e->next; 
        INDIGO_MEM_FREE(e); 
        e = link;
    }
}


indigo_error_t 
indigo_port_desc_stats_get(of_port_desc_stats_reply_t *port_desc_stats_reply)
{
    LOG_TRACE("Port desc_stats_get called");

    return INDIGO_ERROR_NOT_SUPPORTED;
}


/**
 * Currently no experimenter messages supported in the port module
 */

indigo_error_t
indigo_port_experimenter(of_experimenter_t *experimenter,
                         indigo_cxn_id_t cxn_id)
{
    LOG_TRACE("Port experimenter called");

    return INDIGO_ERROR_NOT_SUPPORTED;    
}


/***************************************************************************/

/** \brief Transmit given packet out OF port */

indigo_error_t
indigo_port_packet_emit(of_port_no_t of_port_num,
                        unsigned queue_id,
                        uint8_t *data,
                        unsigned len)
{      
    struct of_port     *p;
  
    LOG_TRACE("Emit %d bytes to port %d, queue %d", 
              len, of_port_num, queue_id);

    if (!of_port_num_valid(of_port_num)) {
        LOG_ERROR("Invalid OF port number");
        return (INDIGO_ERROR_PARAM);
    }

    if (queue_id != 0) {
        LOG_ERROR("Invalid transmit queue");
        return (INDIGO_ERROR_PARAM);
    }

    if (!of_port_inuse(p = of_port_num_to_ptr(of_port_num))) {
        LOG_ERROR("OF port not in use");
        return (INDIGO_ERROR_NOT_FOUND);
    }
    
    if (!OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(p->config, my_config->of_version)
        && !OF_PORT_CONFIG_FLAG_NO_FWD_TEST(p->config, my_config->of_version)
        ) {
        /* Port is enabled and forwarding is enabled for port */
    
        /* Send packet out network interface */
        if (vpi_send(p->vpi, data, len) < 0) {
            LOG_ERROR("vpi_send() failed");
            return (INDIGO_ERROR_UNKNOWN);
        }

        /* Update port stats */

        ++p->cnt_tx_pkts;
        p->cnt_tx_bytes += len;
    }

    return (INDIGO_ERROR_NONE);
}


/**
 * @brief Transmit given packet out a group of ports
 *
 * The only group ID currently supported is "flood".  The value for the
 * flood group is the port-flood id, 0xfffffffb.
 */


indigo_error_t
indigo_port_packet_emit_group(of_port_no_t group_id,
                              of_port_no_t ingress_port_num,
                              uint8_t      *data,
                              unsigned     len
                              )
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct of_port *p;
    unsigned       of_port_num, n;

    LOG_TRACE("Send %d bytes to group 0x%x", len, group_id);

    if (group_id != OF_PORT_DEST_FLOOD) {
        return INDIGO_ERROR_PARAM;
    }

    for (p = of_port_tbl, of_port_num = 1, n = my_config->max_ports;
         n;
         --n, ++of_port_num, ++p
         ) {
        if (!of_port_inuse(p) ||
            of_port_num == ingress_port_num ||
            /* @fixme This is where the assumption is that we're flooding */
            of_port_no_flood(p))  {
            continue;
        }
        result = indigo_port_packet_emit(of_port_num, 0, data, len);
    }

    return (result);
}


/** \brief Transmit given packet out all OF ports, except given one */

indigo_error_t
indigo_port_packet_emit_all(of_port_no_t skip_of_port_num,
                            uint8_t      *data,
                            unsigned     len
                            )
{       
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct of_port *p;
    unsigned       of_port_num, n;

    LOG_TRACE("Emit all, %d bytes", len);

    for (p = of_port_tbl, of_port_num = 1, n = my_config->max_ports;
         n;
         --n, ++of_port_num, ++p
         ) {
        if (!of_port_inuse(p) || of_port_num == skip_of_port_num)  continue;

        result = indigo_port_packet_emit(of_port_num, 0, data, len);
    }

    return (result);
}

/**
 * Set/get the hardware address of the port
 */

indigo_error_t
ind_port_mac_addr_set(of_port_no_t port_no, of_mac_addr_t *mac_addr)
{
    struct of_port *port;

    LOG_TRACE("Setting mac addr of port %d", (int)port_no);

    if (!of_port_num_valid(port_no)) {
        LOG_ERROR("HW addr set: Port number out of range");
        return INDIGO_ERROR_PARAM;
    }

    port = of_port_num_to_ptr(port_no);
    if (!of_port_inuse(port)) {
        LOG_ERROR("Port not in use");
        return INDIGO_ERROR_NOT_FOUND;
    }

    PORTMANAGER_MEMCPY(&port->mac, mac_addr, sizeof(of_mac_addr_t));

    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_port_mac_addr_get(of_port_no_t port_no, of_mac_addr_t *mac_addr)
{
    struct of_port *port;

    LOG_TRACE("Getting mac addr of port %d", (int)port_no);

    if (!of_port_num_valid(port_no)) {
        LOG_ERROR("HW addr set: Port number out of range");
        return INDIGO_ERROR_PARAM;
    }

    port = of_port_num_to_ptr(port_no);
    if (!of_port_inuse(port)) {
        LOG_ERROR("Port not in use");
        return INDIGO_ERROR_NOT_FOUND;
    }

    PORTMANAGER_MEMCPY(mac_addr, &port->mac, sizeof(of_mac_addr_t));

    return INDIGO_ERROR_NONE;
}


/**
 * Set the base hardware address for ports; this has the affect
 * of setting the mac addr for all ports, incrementing by OF port number
 */

indigo_error_t
ind_port_base_mac_addr_set(of_mac_addr_t *base_mac)
{
    struct of_port *port;
    of_mac_addr_t mac_addr;
    int n;

    LOG_TRACE("Setting base mac addr for ports");

    PORTMANAGER_MEMCPY(&mac_addr, base_mac, sizeof(mac_addr));
    for (port = of_port_tbl, n = my_config->max_ports; n; --n, ++port) {
        PORTMANAGER_MEMCPY(&port->mac, &mac_addr, sizeof(of_mac_addr_t));
        /* We only roll over on the lower 3 bytes to leave OUI alone  */
        if (++(mac_addr.addr[5]) == 0) {
            if (++(mac_addr.addr[4]) == 0) {
                ++(mac_addr.addr[3]);
            }
        }
    }


    return INDIGO_ERROR_NONE;
}


/***************************************************************************/

/** \brief Initialize module */

indigo_error_t
ind_port_init(ind_port_config_t *config)
{
    LOG_TRACE("Init called");
    vpi_init();
    *my_config = *config;

    ind_cfg_register(&ind_port_cfg_ops);

    init_done = 1;

    return (of_port_tbl_init());
}


indigo_error_t
ind_port_enable_set(int enable)
{
    LOG_TRACE("Enable set to %d", enable);
    module_enabled = enable;
    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_port_enable_get(int *enable)
{
    if (enable == NULL) {
        return INDIGO_ERROR_PARAM;
    }
    *enable = module_enabled;
    return INDIGO_ERROR_NONE;
}



/** \brief Tear down module */

indigo_error_t
ind_port_finish(void)
{
    LOG_TRACE("Finish called");
    of_port_tbl_delete();

    init_done = 0;

    return (INDIGO_ERROR_NONE);
}

/** \brief Return if packet_in is enabled for given OF port */

unsigned
ind_port_packet_in_is_enabled(of_port_no_t of_port_num)
{
    return (!OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(
        of_port_num_to_ptr(of_port_num)->config,
        my_config->of_version));
}
