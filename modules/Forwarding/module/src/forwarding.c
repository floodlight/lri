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
 * @brief Implementation of Forwarding Component for Indigo Linux Ref
 */

#include "forwarding_log.h"
#include "forwarding_int.h"
#include <Forwarding/forwarding_porting.h>

#include <indigo/memory.h>
#include <AIM/aim.h>
#include <PPE/ppe.h>
#include <FME/fme.h>
#include <FME/fme_types.h>
#include <IOF/iof.h>
#include <Forwarding/forwarding.h>
#include <PortManager/portmanager.h>
#include <Configuration/configuration.h>
#include <cjson/cJSON.h>

static const char __file__[] = "$Id$";

static int init_done = 0;

#define LOXI_SUCCESS(x)  ((x) == OF_ERROR_NONE)
#define LOXI_FAILURE(x)  (!LOXI_SUCCESS(x))

#define FME_FAILURE(x)  ((x) < 0)
#define FME_SUCCESS(x)  (!FME_FAILURE(x))

#define PPE_FAILURE(x)  ((x) < 0)
#define PPE_SUCCESS(x)  (!PPE_FAILURE(x))

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))

/* Short hand logging macros */
#define LOG_ERROR AIM_LOG_ERROR
#define LOG_WARN AIM_LOG_WARN 
#define LOG_INFO AIM_LOG_INFO
#define LOG_VERBOSE AIM_LOG_VERBOSE
#define LOG_TRACE AIM_LOG_TRACE

static ind_fwd_config_t my_config[1];

static fme_t* fme; 

static unsigned active_count;   /**< Number of flows defined */
static uint64_t lookup_count;   /**< Number of packets looked up */
static uint64_t matched_count;  /**< Number of packets matched */

static int module_enabled = 0; /**< Module enable state */

static int expiration_enabled = 1;

static int
fme_key_mask_dump__(fme_key_t* key, aim_pvs_t* pvs)
{
    iof_t iof; 
    iof_init(&iof, pvs); 
    iof_push(&iof, "keymask = 0x%.8x", key->keymask);
    if(key->keymask) { 
        ppe_header_t h; 
        iof_indent(&iof); 
        for(h = 0; h <= PPE_HEADER_LAST; h++) {
            if(key->keymask & (1<<h)) { 
                iof_uprintf(&iof, "%s ", ppe_header_name(h)); 
            }
        }
        iof_uprintf(&iof, "\n"); 
    }
    iof_pop(&iof); 
    return 0; 
}

                 
/**
 * Dump a packet key
 */  
static int
fme_key_dump_pkey__(fme_key_t* key, aim_pvs_t* pvs)
{
    iof_t iof; 
    ppe_field_t field; 

    iof_init(&iof, pvs); 
    
    iof_push(&iof, "packet fme_key @ %p", key); 

    fme_key_mask_dump__(key, &iof.inherit);
    iof_iprintf(&iof, "size = %d", key->size); 
    iof_iprintfn(&iof, "value: "); 


    for(field = PPE_FIELD_OF10_FIRST+1; 
        field < PPE_FIELD_OF10_LAST; field++) {
        const ppe_field_info_t* fi = ppe_field_info_get(field); 
        if(fi->size_bits <= 32) {
            uint32_t v; 
            ppe_field_get_header(key->values, field, &v); 
            if(v == 0) { 
                iof_uprintf(&iof, "%s=0 ", ppe_field_name(field)); 
            }
            else {
                iof_uprintf(&iof, "%s=0x%.8x ", ppe_field_name(field), v); 
            }
        }
        else { 
            /* todo */
        }
    }
    iof_uprintf(&iof, "\n"); 
    iof_pop(&iof); 
    return 0; 
}

static int 
fme_key_dump_mkey__(fme_key_t* key, aim_pvs_t* pvs)
{       
    iof_t iof; 
    ppe_field_t field; 

    iof_init(&iof, pvs); 
    iof_push(&iof, "entry fme_key @ %p", key); 
    fme_key_mask_dump__(key, &iof.inherit); 
    iof_iprintf(&iof, "size = %d", key->size); 
    iof_iprintfn(&iof, "keys: "); 

    for(field = PPE_FIELD_OF10_FIRST+1; 
        field < PPE_FIELD_OF10_LAST; field++) { 
        const ppe_field_info_t* fi = ppe_field_info_get(field); 
        if(fi->size_bits <= 32) { 
            uint32_t v; 
            uint32_t m; 
            ppe_field_get_header(key->values, field, &v); 
            ppe_field_get_header(key->masks, field, &m); 
            if(v == 0 && m == 0) {
                /* Not relevant. */
                continue; 
            }
            iof_uprintf(&iof, "%s=%x:%x ", ppe_field_name(field), 
                        v, m); 
        }
        else {
            /* todo */
        }
    }
    iof_uprintf(&iof, "\n"); 
    iof_pop(&iof); 
    return 0; 
}


/**
 * Stats for packet in
 */
uint64_t ind_fwd_packet_in_packets;
uint64_t ind_fwd_packet_in_bytes;
uint64_t ind_fwd_packet_out_packets;
uint64_t ind_fwd_packet_out_bytes;

/** \brief Get forwarding features */

indigo_error_t
indigo_fwd_forwarding_features_get(of_features_reply_t *features)
{
    uint32_t capabilities = 0, actions = 0;

    OF_CAPABILITIES_FLAG_FLOW_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_TABLE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_PORT_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_QUEUE_STATS_SET(capabilities, features->version);
    OF_CAPABILITIES_FLAG_ARP_MATCH_IP_SET(capabilities, features->version);

    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_OUTPUT_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions, 
        OF_ACTION_TYPE_SET_VLAN_VID_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_VLAN_PCP_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_STRIP_VLAN_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_DL_SRC_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_DL_DST_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_SRC_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_DST_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_NW_TOS_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_TP_SRC_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_SET_TP_DST_BY_VERSION(features->version));
    OF_FLAG_ENUM_SET(actions,
        OF_ACTION_TYPE_ENQUEUE_BY_VERSION(features->version));

    of_features_reply_n_tables_set(features, 1);
    of_features_reply_capabilities_set(features, capabilities);
    /* Only 1.0 has actions in switch features */
    if (features->version == OF_VERSION_1_0) {
        of_features_reply_actions_set(features, actions);
    }
    
    return (INDIGO_ERROR_NONE);
}


struct fme_flow_data {
    indigo_cookie_t  flow_id;         /* Flow id */
    fme_entry_t*     fme_entry;       /* FME entry */
    of_list_action_t *of_list_action; /* List of actions for flow */
    uint64_t         cnt_pkts;        /* Running count of matched packets */
    uint64_t         cnt_bytes;       /* Running sum of sizes of matched packets */
};

#define FLOW_ID_HASH_TABLE_LEN 64 /* Size must be power of 2 */
static biglist_t *flow_id_ht[FLOW_ID_HASH_TABLE_LEN];

static unsigned
flow_id_hash(indigo_cookie_t flow_id)
{
   return (((unsigned) flow_id) & (ARRAY_SIZE(flow_id_ht) - 1));
}

static void
flow_id_dict_insert(struct fme_flow_data *fme_flow_data)
{
   /* N.B. No check made for duplicate flow_ids */

   biglist_t **b = &flow_id_ht[flow_id_hash(fme_flow_data->flow_id)];

   *b = biglist_append(*b, fme_flow_data);
}

static void
flow_id_dict_erase(indigo_cookie_t flow_id)
{
   /* N.B. No check made for deleting something not there */

   biglist_t **b = &flow_id_ht[flow_id_hash(flow_id)], *bl = *b, *ble;
   struct fme_flow_data *fme_flow_data;

   BIGLIST_FOREACH(ble, bl) {
      fme_flow_data = BIGLIST_CAST(struct fme_flow_data *, ble);
      if (fme_flow_data->flow_id == flow_id) {
         *b = biglist_remove(*b, fme_flow_data);
         break;
      }
   }
}

static struct fme_flow_data *
flow_id_dict_find(indigo_cookie_t flow_id)
{
   biglist_t *bl = flow_id_ht[flow_id_hash(flow_id)], *ble;
   struct fme_flow_data *p;

   BIGLIST_FOREACH(ble, bl) {
      p = BIGLIST_CAST(struct fme_flow_data *, ble);
      if (p->flow_id == flow_id)  return (p);
   }

   return (0);
}


/** \brief Create a flow */

void
indigo_fwd_flow_create(indigo_cookie_t flow_id,
                       of_flow_add_t   *flow_add,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t       result          = INDIGO_ERROR_NONE;
    fme_entry_t*          fme_entry       = 0;
    struct fme_flow_data *fme_flow_data  = 0;
    of_list_action_t     *of_list_action = 0;
    uint16_t             pri;
    of_match_t           of_match[1];
    fme_key_t           fme_key; 
    extern int fme_oc_printf(void*, const char*, ...); 

    LOG_TRACE("Flow create called");
    fme_flow_data = (struct fme_flow_data *) 
        INDIGO_MEM_ALLOC(sizeof(struct fme_flow_data));
    if (fme_flow_data == NULL) {
        LOG_ERROR("INDIGO_MEM_ALLOC() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    memset(fme_flow_data, 0, sizeof(*fme_flow_data));

    of_flow_add_priority_get(flow_add, &pri);
    if (LOXI_FAILURE(of_flow_add_match_get(flow_add,
                                           of_match
                                           )
                     )
        ) {
        LOG_ERROR("of_flow_add_match_get() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    of_list_action = of_flow_add_actions_get(flow_add);
    if (of_list_action == NULL) {
        LOG_ERROR("of_flow_add_actions_get() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    fme_flow_data->of_list_action = of_list_action;


    LOG_TRACE("Adding flow to FME");
    if (FME_FAILURE(fme_entry_create(&fme_entry))) {
        LOG_ERROR("fme_entry_create() failed");
        result = INDIGO_ERROR_UNKNOWN; /** \todo Check for table overflow? */
        goto done;
    }

    fme_entry->prio = pri; 
    fme_entry->cookie = fme_flow_data; 
    fme_flow_data->fme_entry = fme_entry;
    
    FME_MEMSET(&fme_key, 0, sizeof(fme_key)); 

    /*
     * We use the OF10 header as the key. 
     */
    fme_key.size = ppe_field_info_table[PPE_FIELD_OF10_LAST].offset_bytes; 
    fme_key.dumper = fme_key_dump_mkey__; 
    
    /* For each match field F,
       if F is specified (i.e. not wildcarded),
       add it to the FME key. 
    */

#define ADD_FME_KEY_FIELD(u, v, w, ph)                                  \
    if (OF_MATCH_MASK_ ## u ## _ACTIVE_TEST(of_match)) {                \
        ppe_field_set_header(fme_key.values, v,                         \
                             (of_match->fields. w) & (of_match->masks. w)); \
        ppe_field_set_header(fme_key.masks, v, of_match->masks. w);     \
        fme_key.keymask |= (1<<ph);                                     \
    }                                                                     
    
#define ADD_FME_KEY_MAC_ADDR(u, v, w)                                   \
    do {                                                                \
        if (OF_MATCH_MASK_ ## u ## _ACTIVE_TEST(of_match)) {            \
            of_mac_addr_t masked_value;                                 \
            int idx;                                                    \
            for (idx = 0; idx < OF_MAC_ADDR_BYTES; idx++) {             \
                masked_value.addr[idx] = (of_match->masks. w .addr)[idx] & \
                    (of_match->fields. w .addr)[idx];                   \
            }                                                           \
            ppe_wide_field_set_header(fme_key.values, v, masked_value.addr); \
            ppe_wide_field_set_header(fme_key.masks, v, of_match->masks. w .addr); \
            fme_key.keymask |= (1<<PPE_HEADER_ETHERNET);                \
        }                                                                   \
    } while (0)

    /** \todo Non-canonical flows? */
    
    ADD_FME_KEY_FIELD(IN_PORT,    PPE_FIELD_OF10_INGRESS_PORT,  in_port, 
                      PPE_HEADER_META);
    ADD_FME_KEY_MAC_ADDR(ETH_SRC, PPE_FIELD_OF10_ETHER_SRC_MAC, eth_src);
    ADD_FME_KEY_MAC_ADDR(ETH_DST, PPE_FIELD_OF10_ETHER_DST_MAC, eth_dst);

    if (OF_MATCH_MASK_VLAN_VID_ACTIVE_TEST(of_match)) {
        if (OF_MATCH_MASK_VLAN_VID_EXACT_TEST(of_match)
            && (of_match->fields.vlan_vid 
                == OF_MATCH_UNTAGGED_VLAN_ID(flow_add->version)
                )
            ) {

            /* Match untagged packets */
            ppe_field_set_header(fme_key.values, PPE_FIELD_OF10_PACKET_FORMAT, 
                                 PPE_HEADER_ETHERII); 
            ppe_field_set_header(fme_key.masks, PPE_FIELD_OF10_PACKET_FORMAT, 
                                 -1);
        } else {
            /* Match tagged packets */
            ppe_field_set_header(fme_key.values, PPE_FIELD_OF10_PACKET_FORMAT, 
                                 PPE_HEADER_8021Q); 
            ppe_field_set_header(fme_key.masks, PPE_FIELD_OF10_PACKET_FORMAT, 
                                 -1); 
            ADD_FME_KEY_FIELD(VLAN_VID, PPE_FIELD_OF10_VLAN, vlan_vid, 
                              PPE_HEADER_8021Q);
            ADD_FME_KEY_FIELD(VLAN_PCP, PPE_FIELD_OF10_PRI,  vlan_pcp, 
                              PPE_HEADER_8021Q);
        }
    }

    ADD_FME_KEY_FIELD(ETH_TYPE,    PPE_FIELD_OF10_ETHER_TYPE, eth_type, 
                      PPE_HEADER_ETHER);

    /**
     * Special case handling for Arp packets. 
     *
     * When a flowmod is specified with ethertype == ARP there is a 
     * special interpretation of the source/dest/protocol fields in 
     * the flowmod. 
     *
     * For IPv4 ARP flows the following mapping should be performed:
     *    NW_PROTO -> ARP OPERATION
     *    NW_SRC -> ARP Source Protocol Address
     *    NW_DST -> ARP Target Protocol Address. 
     *
     * This applies to ARP Protocol Type == 0x800 only, so an implicit
     * qualification on this must also be added. 
     *
     * @fixme constants
     */
    if (OF_MATCH_MASK_ETH_TYPE_ACTIVE_TEST(of_match) && 
        of_match->fields.eth_type == 0x0806 &&
        of_match->masks.eth_type == 0xffff) {

        ppe_field_set_header(fme_key.values, PPE_FIELD_OF10_ARP_PTYPE, 
                             0x0800); 
        ppe_field_set_header(fme_key.masks,  PPE_FIELD_OF10_ARP_PTYPE, 
                             0xFFFF); 
        ADD_FME_KEY_FIELD(IPV4_SRC, PPE_FIELD_OF10_ARP_SPA, ipv4_src, 
                          PPE_HEADER_ARP); 
        ADD_FME_KEY_FIELD(IPV4_DST, PPE_FIELD_OF10_ARP_TPA, ipv4_dst, 
                          PPE_HEADER_ARP); 
        ADD_FME_KEY_FIELD(IP_PROTO, PPE_FIELD_OF10_ARP_OPERATION, ip_proto, 
                          PPE_HEADER_ARP); 
        
    }
    
    /**
     * Special case LLC/SNAP Processing. 
     *
     * If the specified ethertype is 0x5FF, then match
     * all Non-ethertype packets (LLC-only, or SNAP with OUI != 0). 
     * 
     * In this case we merely qualify the headermask with ETHERTYPE_MISSING. 
     * 
     */
    else if(OF_MATCH_MASK_ETH_TYPE_ACTIVE_TEST(of_match) && 
            of_match->fields.eth_type == 0x5FF) { 
        fme_key.keymask = (1<<PPE_HEADER_ETHERTYPE_MISSING); 
        ppe_field_set_header(fme_key.values, PPE_FIELD_OF10_ETHER_TYPE, 0);
        ppe_field_set_header(fme_key.masks, PPE_FIELD_OF10_ETHER_TYPE, 0);
    }

    /**
     * Normal field mapping applies. 
     */
    else {

        ADD_FME_KEY_FIELD(IP_DSCP,     PPE_FIELD_OF10_IP4_TOS,      ip_dscp, 
                          PPE_HEADER_IP4);
        ADD_FME_KEY_FIELD(IP_PROTO,    PPE_FIELD_OF10_IP4_PROTO,   ip_proto, 
                          PPE_HEADER_IP4);
        ADD_FME_KEY_FIELD(IPV4_SRC,    PPE_FIELD_OF10_IP4_SRC_ADDR, ipv4_src, 
                          PPE_HEADER_IP4);
        ADD_FME_KEY_FIELD(IPV4_DST,    PPE_FIELD_OF10_IP4_DST_ADDR, ipv4_dst, 
                          PPE_HEADER_IP4);
        ADD_FME_KEY_FIELD(TCP_SRC,     PPE_FIELD_OF10_L4_SRC_PORT,  tcp_src, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(TCP_DST,     PPE_FIELD_OF10_L4_DST_PORT,  tcp_dst, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(UDP_SRC,     PPE_FIELD_OF10_L4_SRC_PORT,  udp_src, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(UDP_DST,     PPE_FIELD_OF10_L4_DST_PORT,  udp_dst, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(SCTP_SRC,    PPE_FIELD_OF10_L4_SRC_PORT,  sctp_src, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(SCTP_DST,    PPE_FIELD_OF10_L4_DST_PORT,  sctp_dst, 
                          PPE_HEADER_L4);
        ADD_FME_KEY_FIELD(ICMPV4_TYPE, PPE_FIELD_OF10_ICMP_TYPE,    icmpv4_type, 
                          PPE_HEADER_ICMP);
        ADD_FME_KEY_FIELD(ICMPV4_CODE, PPE_FIELD_OF10_ICMP_CODE,    icmpv4_code, 
                          PPE_HEADER_ICMP);

    }


    {
        time_t   now;
        uint16_t tmout;

        time(&now);

        of_flow_add_hard_timeout_get(flow_add, &tmout);
        if (tmout != 0) { 
            fme_entry->absolute_timeout = now + tmout; 
        }
        of_flow_add_idle_timeout_get(flow_add, &tmout);
        if (tmout != 0) { 
            fme_entry->relative_timeout = tmout; 
        }
    }

    fme_entry_key_set(fme_entry, &fme_key); 
    if(FME_FAILURE(fme_add_entry(fme, fme_entry))) {
        LOG_ERROR("fme_add_entry() failed"); 
        result = INDIGO_ERROR_UNKNOWN; 
        goto done; 
    }

    fme_flow_data->flow_id = flow_id;

    flow_id_dict_insert(fme_flow_data);
    
    ++active_count;


 done:
    if (INDIGO_FAILURE(result)) {
        if (of_list_action)  of_list_action_delete(of_list_action);
        if (fme_entry)       fme_entry_destroy(fme_entry);
        if (fme_flow_data)   INDIGO_MEM_FREE(fme_flow_data);
    }

    indigo_core_flow_create_callback(result,
                                     flow_id,
                                     0, /* @FIXME hardcoded table id */
                                     callback_cookie);
}


/** \brief Modify a flow */

void
indigo_fwd_flow_modify(indigo_cookie_t flow_id,
                       of_flow_modify_t *flow_modify,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t       result = INDIGO_ERROR_NONE;
    struct fme_flow_data *fme_flow_data;
    of_list_action_t     *of_list_action = 0, *old_of_list_action;

    if ((fme_flow_data = flow_id_dict_find(flow_id)) == 0) {
       LOG_ERROR("Flow not found");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    /* @todo Fill in flow_modify if non-NULL */
    LOG_TRACE("Flow modify called\n");

    of_list_action = of_flow_modify_strict_actions_get(flow_modify);
    if (of_list_action == NULL) {
        LOG_ERROR("of_flow_modify_actions_get() failed to get actions");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    old_of_list_action = fme_flow_data->of_list_action;
    fme_flow_data->of_list_action = of_list_action;
    of_list_action_delete(old_of_list_action);  /* Free old action list */

    /** \todo Clear flow stats? */

 done:
    if (INDIGO_FAILURE(result)) {
        of_list_action_delete(of_list_action);
    }

    indigo_core_flow_modify_callback(result, NULL, callback_cookie);
}


/** \brief Delete a flow */

void
indigo_fwd_flow_delete(indigo_cookie_t flow_id,
                       indigo_cookie_t callback_cookie)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    struct fme_flow_data *fme_flow_data;
    indigo_fi_flow_stats_t flow_stats;

    if ((fme_flow_data = flow_id_dict_find(flow_id)) == 0) {
       LOG_INFO("Request to delete non-existent flow");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    flow_stats.packets = fme_flow_data->cnt_pkts;
    flow_stats.bytes = fme_flow_data->cnt_bytes;
    flow_stats.flow_id = flow_id;

    fme_remove_entry(fme, fme_flow_data->fme_entry); 
    fme_entry_destroy(fme_flow_data->fme_entry); 

    /* @fixme Get duration from FME data? */

    of_list_action_delete(fme_flow_data->of_list_action);

    flow_id_dict_erase(flow_id);

    INDIGO_MEM_FREE(fme_flow_data);

    --active_count;

  done:
    indigo_core_flow_delete_callback(result, &flow_stats,
                                     callback_cookie);

}


/** \brief Get flow statistics */

void
indigo_fwd_flow_stats_get(indigo_cookie_t flow_id,
                          indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    struct fme_flow_data *fme_flow_data;
    indigo_fi_flow_stats_t flow_stats;

    if ((fme_flow_data = flow_id_dict_find(flow_id)) == 0) {
       LOG_ERROR("Flow not found");
       result = INDIGO_ERROR_NOT_FOUND;
       goto done;
    }

    flow_stats.packets = fme_flow_data->cnt_pkts;
    flow_stats.bytes   = fme_flow_data->cnt_bytes;
    flow_stats.flow_id = flow_id;

    /* @fixme Get duration from FME data? */

  done:

    indigo_core_flow_stats_get_callback(result, &flow_stats,
                                        callback_cookie);
}


/** \brief Get table statistics */

void
indigo_fwd_table_stats_get(of_table_stats_request_t *table_stats_request,
                           indigo_cookie_t callback_cookie)
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    of_list_table_stats_entry_t *of_list_table_stats_entry = 0;
    of_table_stats_entry_t *of_table_stats_entry = 0;
    of_table_stats_reply_t *table_stats_reply;
    of_version_t version;
    uint32_t xid;
    of_table_name_t table_name;

    version = table_stats_request->version;

    table_stats_reply = of_table_stats_reply_new(version);
    if (table_stats_reply == NULL) {
        LOG_ERROR("of_list_table_stats_reply_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_table_stats_entry = of_list_table_stats_entry_new(version)) == 0) {
        LOG_ERROR("of_list_table_stats_entry_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_table_stats_entry = of_table_stats_entry_new(version)) == 0) {
        LOG_ERROR("of_table_stats_entry_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_table_stats_request_xid_get(table_stats_request, &xid);
    of_table_stats_reply_xid_set(table_stats_reply, xid);

    of_table_stats_entry_table_id_set(of_table_stats_entry, 0);
    FORWARDING_MEMSET(table_name, 0, sizeof(table_name));
    strcpy(table_name, "Table 0");
    of_table_stats_entry_name_set(of_table_stats_entry, table_name);
    {
        const of_wc_bmap_t of_wc_bmap = 0x3fffff; /* All wildcards */
        of_table_stats_entry_wildcards_set(of_table_stats_entry, of_wc_bmap);
    }
    of_table_stats_entry_max_entries_set(of_table_stats_entry,
                                         my_config->max_flows);
    /* NOTE:  Active count is overridden by state manager */
    of_table_stats_entry_active_count_set(of_table_stats_entry, active_count);
    of_table_stats_entry_lookup_count_set(of_table_stats_entry, lookup_count);
    of_table_stats_entry_matched_count_set(of_table_stats_entry, matched_count);
    
    if (LOXI_FAILURE(of_list_table_stats_entry_append(of_list_table_stats_entry, of_table_stats_entry))) {
        LOG_ERROR("of_list_table_state_entry_append() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
        
    if (LOXI_FAILURE(of_table_stats_reply_entries_set(table_stats_reply, of_list_table_stats_entry))) {
        LOG_ERROR("of_table_stats_reply_entries_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    of_table_stats_entry_delete(of_table_stats_entry);
    of_list_table_stats_entry_delete(of_list_table_stats_entry);

    indigo_core_table_stats_get_callback(result, table_stats_reply,
                                         callback_cookie);
}

/**
 * brief Convert a packet to dot1q if necessary
 */
static indigo_error_t
convert_to_dot1q(ppe_packet_t* ppep)
{
    int rv;
    ppe_header_t header; 
    
    ppe_packet_format_get(ppep, &header); 

    if (header != PPE_HEADER_8021Q) {
        rv = ppe_packet_format_set(ppep, PPE_HEADER_8021Q); 
        if (PPE_FAILURE(rv)) {
            LOG_ERROR("Failed to convert pkt to .1q");
            return INDIGO_ERROR_UNKNOWN;
        }
        rv = ppe_field_set(ppep, PPE_FIELD_8021Q_TPID, 0x8100);
        if (PPE_FAILURE(rv)) {
            LOG_ERROR("Failed to set tpid converting to .1q");
            return INDIGO_ERROR_UNKNOWN;
        }
    }
    
    return INDIGO_ERROR_NONE;
}

/** \brief Send a "packet in" notification to the state manager */

static indigo_error_t
pkt_in(ppe_packet_t *ppep, unsigned reason)
{
    indigo_error_t result        = INDIGO_ERROR_NONE;
    of_packet_in_t     *of_packet_in = 0;
    of_octets_t        of_octets[1];
    of_version_t version;
    uint32_t in_port; 

    /* Since we don't know the version of the cxn, use configured version */
    version = my_config->of_version;
    
    ppe_field_get(ppep, PPE_FIELD_META_INGRESS_PORT, &in_port); 

    if (!ind_port_packet_in_is_enabled(in_port)) { 
        LOG_TRACE("Packet in not enabled");
        goto done;
    }
  
    if ((of_packet_in = of_packet_in_new(version)) == 0) {
        LOG_ERROR("of_packet_in_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    /** \todo Who sets buffer_id? */

    of_packet_in_total_len_set(of_packet_in, ppep->size);
    of_packet_in_in_port_set(of_packet_in, 
                             in_port); 
    of_packet_in_reason_set(of_packet_in, reason);
    of_packet_in_buffer_id_set(of_packet_in, OF_BUFFER_ID_NO_BUFFER);
    of_octets->data  = ppep->data;
    of_octets->bytes = ppep->size;
    if (LOXI_FAILURE(of_packet_in_data_set(of_packet_in, of_octets))) {
        LOG_ERROR("of_packet_in_data_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    ++ind_fwd_packet_in_packets;
    ind_fwd_packet_in_bytes += ppep->size;

    (void)indigo_core_packet_in(of_packet_in);
  
    of_packet_in = 0;     /* No longer owned */
  
 done:
    if (of_packet_in)  of_packet_in_delete(of_packet_in);

    return (result);
}


indigo_error_t
indigo_fwd_packet_receive(of_port_no_t of_port_num,
                          uint8_t      *data,
                          unsigned     len
                          );

/** \brief Perform flow action on packet */

static indigo_error_t
pkt_action_do(of_port_no_t   in_port,
              ppe_packet_t* ppep, 
              of_action_t    *of_action
              )
{
    indigo_error_t result = INDIGO_ERROR_NONE;
    int rv;
    uint32_t ingress_port; 

    /* @fixme check array ref */
    LOG_TRACE("Processing action %s", 
              of_object_id_str[of_action->header.object_id]);

    ppe_field_get(ppep, PPE_FIELD_META_INGRESS_PORT, &ingress_port); 

    switch (of_action->header.object_id) {
    case OF_ACTION_ENQUEUE:
        {
            of_port_no_t of_port_num;
            uint32_t     of_queue_id;

            /** \todo Handle special ports? */

            of_action_enqueue_port_get(&of_action->enqueue, &of_port_num);
            of_action_enqueue_queue_id_get(&of_action->enqueue, &of_queue_id);

            if (of_port_num == OF_PORT_DEST_CONTROLLER) {
                /** @fixme Validate queue ID is okay for controller */
                if (INDIGO_FAILURE(result = pkt_in(ppep,
                                                   OF_PACKET_IN_REASON_ACTION
                                                   )
                                   )
                    ) {
                    LOG_ERROR("of_packet_in() failed for enqueue");
                }
            } else {
                result = indigo_port_packet_emit(of_port_num,
                                                 of_queue_id,
                                                 ppep->data,
                                                 ppep->size
                                                 );
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("of_dp_portman_pkt_tx() failed");
                }
            }
        }
        break;
    case OF_ACTION_OUTPUT:
        {
            of_port_no_t of_port_num;
            of_action_output_port_get(&of_action->output, &of_port_num);
            switch (of_port_num) {
            case OF_PORT_DEST_CONTROLLER:
                if (INDIGO_FAILURE(result = pkt_in(ppep,
                                                   OF_PACKET_IN_REASON_ACTION
                                                   )
                                   )
                    ) {
                    LOG_ERROR("of_packet_in() failed");
                }
                break;
            case OF_PORT_DEST_FLOOD:
                result = indigo_port_packet_emit_group(
                    OF_PORT_DEST_FLOOD,
                    ingress_port, 
                    ppep->data,
                    ppep->size);
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("of_port_packet_emit_group() failed");
                }
                break;
            case OF_PORT_DEST_ALL:
                result = indigo_port_packet_emit_all(
                                                     ingress_port, 
                    ppep->data,
                                                     ppep->size);
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("of_port_packet_emit() failed");
                }
                break;
            case OF_PORT_DEST_USE_TABLE:
                result = indigo_fwd_packet_receive(in_port,
                                                   ppep->data,
                                                   ppep->size
                                                   );
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("of_fwd_packet_receive() failed");
                }
                break;
            case OF_PORT_DEST_IN_PORT:
                of_port_num = ingress_port; 
                /* Fall through */
            default:
                result = indigo_port_packet_emit(of_port_num,
                                                 0,
                                                 ppep->data,
                                                 ppep->size);
                if (INDIGO_FAILURE(result)) {
                    LOG_ERROR("of_port_packet_emit() failed");
                }
            }
        }
        break;
    case OF_ACTION_SET_DL_DST:
        {
            of_mac_addr_t of_mac_addr[1];
            unsigned char *p;

            of_action_set_dl_dst_dl_addr_get(&of_action->set_dl_dst, of_mac_addr);

            if ((p = ppe_fieldp_get(ppep, PPE_FIELD_ETHERNET_DST_MAC))
                == 0
                ) {
                LOG_ERROR("ppe_fieldp_get() failed");
                result = INDIGO_ERROR_UNKNOWN;
                break;
            }

            memcpy(p, of_mac_addr->addr, sizeof(of_mac_addr->addr));
        }
        break;
    case OF_ACTION_SET_DL_SRC:
        {
            of_mac_addr_t of_mac_addr[1];
            unsigned char *p;

            of_action_set_dl_src_dl_addr_get(&of_action->set_dl_src, of_mac_addr);

            if ((p = ppe_fieldp_get(ppep, PPE_FIELD_ETHERNET_SRC_MAC))
                == 0
                ) {
                LOG_ERROR("ppe_fieldp_get() failed");
                result = INDIGO_ERROR_UNKNOWN;
                break;
            }

            memcpy(p, of_mac_addr->addr, sizeof(of_mac_addr->addr));
        }
        break;
    case OF_ACTION_SET_NW_DST:
        {
            uint32_t nw_dst;
            of_action_set_nw_dst_nw_addr_get(&of_action->set_nw_dst, &nw_dst);

            if (PPE_FAILURE(ppe_field_set(ppep, 
                                          PPE_FIELD_IP4_DST_ADDR, 
                                          nw_dst
                                          )
                            )
                ) {
                LOG_ERROR("ppe_field_set) failed for IP4_DST_ADDR");
                result = INDIGO_ERROR_UNKNOWN;
            }
            if (PPE_FAILURE(ppe_packet_update(ppep))) { 
                LOG_ERROR("Packet Update for NW DST failed");
                result = INDIGO_ERROR_UNKNOWN;
            }  
            LOG_ERROR("SET_NW_DST result=%d", result); 
        }
        break;
    case OF_ACTION_SET_NW_SRC:
        {
            uint32_t nw_src;
            of_action_set_nw_src_nw_addr_get(&of_action->set_nw_src, &nw_src);

            if (PPE_FAILURE(ppe_field_set(ppep,
                                             PPE_FIELD_IP4_SRC_ADDR,
                                             nw_src
                                             )
                                )
                ) {
                LOG_ERROR("ppe_field_set() failed for ip4src");
                result = INDIGO_ERROR_UNKNOWN;
            }
            if (PPE_FAILURE(ppe_packet_update(ppep))) {
                LOG_ERROR("Packet Update for NW SRC failed");
                result = INDIGO_ERROR_UNKNOWN;
            }            
        }
        break;
    case OF_ACTION_SET_NW_TOS:
        {
            uint8_t nw_tos;
            of_action_set_nw_tos_nw_tos_get(&of_action->set_nw_tos, &nw_tos);

            if (PPE_FAILURE(ppe_field_set(ppep,
                                             PPE_FIELD_IP4_TOS,
                                             nw_tos
                                             )
                                )
                ) {
                LOG_ERROR("ppe_field_set() failed for ip4 tos");
                result = INDIGO_ERROR_UNKNOWN;
            }
            if (PPE_FAILURE(ppe_packet_update(ppep))) {
                LOG_ERROR("Packet Update for NW TOS failed");
                result = INDIGO_ERROR_UNKNOWN;
            }            
        }
        break;
    case OF_ACTION_SET_TP_DST:
        {
            uint16_t tp_dst;
            of_action_set_tp_dst_tp_port_get(&of_action->set_tp_dst, &tp_dst);

            if (PPE_FAILURE(ppe_field_set(ppep,
                                          PPE_FIELD_L4_DST_PORT,
                                             tp_dst
                                             )
                                )
                ) {
                LOG_ERROR("ppe_field_set() failed for L4 dest");
                result = INDIGO_ERROR_UNKNOWN;
            }
            if (PPE_FAILURE(ppe_packet_update(ppep))) {
                LOG_ERROR("Packet Update for TP DST failed");
                result = INDIGO_ERROR_UNKNOWN;
            }            
        }
        break;
    case OF_ACTION_SET_TP_SRC:
        {
            uint16_t tp_src;
            of_action_set_tp_src_tp_port_get(&of_action->set_tp_src, &tp_src);

            if (PPE_FAILURE(ppe_field_set(ppep,
                                             PPE_FIELD_L4_SRC_PORT,
                                             tp_src
                                             )
                                )
                ) {
                LOG_ERROR("ppe_field_set() failed for L4 src");
                result = INDIGO_ERROR_UNKNOWN;
            }
            if (PPE_FAILURE(ppe_packet_update(ppep))) {
                LOG_ERROR("Packet Update for TP SRC failed");
                result = INDIGO_ERROR_UNKNOWN;
            }            
        }
        break;
    case OF_ACTION_SET_VLAN_PCP:
        {
            uint8_t vlan_pcp;
            of_action_set_vlan_pcp_vlan_pcp_get(&of_action->set_vlan_pcp, &vlan_pcp);

            if ((result = convert_to_dot1q(ppep)) < 0) {
                break;
            }
            if (PPE_FAILURE(ppe_field_set(ppep,
                                             PPE_FIELD_8021Q_PRI,
                                             vlan_pcp
                                             )
                                )
                ) {
                LOG_ERROR("ppe_field_set() failed for .1q pri");
                result = INDIGO_ERROR_UNKNOWN;
            }
        }
        break;
    case OF_ACTION_SET_VLAN_VID:
        {
            uint16_t vlan_vid;
            of_action_set_vlan_vid_vlan_vid_get(&of_action->set_vlan_vid, &vlan_vid);

            if ((result = convert_to_dot1q(ppep)) < 0) {
                break;
            }
            rv = ppe_field_set(ppep, PPE_FIELD_8021Q_VLAN, vlan_vid);
            if (PPE_FAILURE(rv)) {
                LOG_ERROR("ppe_field_set() failed for .1q vlan");
                result = INDIGO_ERROR_UNKNOWN;
            }
        }
        break;
    case OF_ACTION_STRIP_VLAN:
        LOG_TRACE("Strip VLAN tag action");
        rv = ppe_packet_format_set(ppep, PPE_HEADER_ETHERII); 
        if (PPE_FAILURE(rv)) {
            LOG_ERROR("Failed to convert pkt to EtherII");
            result = INDIGO_ERROR_UNKNOWN;
        }
        break;
    case OF_ACTION_BSN_MIRROR:
        LOG_TRACE("BSN Mirror action: Skipping (not yet implemented)");
        /* @fixme implement */
        break;
    default:
        LOG_ERROR("Unsupported or invalid action: %d",
                  of_action->header.object_id);
        result = INDIGO_ERROR_NOT_SUPPORTED;
    }

    return (result);
}


static indigo_error_t
ppe_pkt_setup(of_port_no_t   of_port_num,
              uint8_t        *data,
              unsigned       len, 
              ppe_packet_t*  ppep)
{

    ppe_packet_init(ppep, data, len); 
    
    if(ppe_parse(ppep) < 0) { 
        LOG_ERROR("ppe_parse() failed at setup");
        return (INDIGO_ERROR_UNKNOWN);
    }
    
    ppe_field_set(ppep, PPE_FIELD_META_INGRESS_PORT, of_port_num); 

    return (INDIGO_ERROR_NONE);
}

static indigo_error_t
fme_key_setup(ppe_packet_t* ppep, fme_key_t* key)
{
    FME_MEMSET(key, 0, sizeof(*key)); 
    key->size = ppe_field_info_table[PPE_FIELD_OF10_LAST].offset_bytes; 
    key->dumper = fme_key_dump_pkey__; 
    FME_MEMSET(key->values, 0, key->size); 
    FME_MEMSET(key->masks, 0, key->size); 

    /**
     *  Set the OpenFlow 1.0 header in the packet and
     * copy the packet fields into the key. 
     */
    ppe_header_set(ppep, PPE_HEADER_OF10, key->values); 
    
    /*
     * We use the header mask as the keymask for matches
     */
    key->keymask = ppep->header_mask; 
    
    /**
     * Copy all relevent fields from the packet to the OF10 header, 
     * which is currently storing our key. 
     *
     * We don't bother checking whether the field exists or not -- 
     * if it fails, it won't be in the header_mask to begin with, 
     * and therefore not in the keymask, and won't be matched. 
     */
    ppe_wide_field_copy(ppep, PPE_FIELD_OF10_ETHER_DST_MAC, 
                        PPE_FIELD_ETHERNET_DST_MAC); 
    ppe_wide_field_copy(ppep, PPE_FIELD_OF10_ETHER_SRC_MAC, 
                        PPE_FIELD_ETHERNET_SRC_MAC); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ETHER_TYPE, 
                   PPE_FIELD_ETHER_TYPE); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_TPID, PPE_FIELD_8021Q_TPID); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_PRI, PPE_FIELD_8021Q_PRI); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_CFI, PPE_FIELD_8021Q_CFI); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_VLAN, PPE_FIELD_8021Q_VLAN); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_IP4_DST_ADDR, PPE_FIELD_IP4_DST_ADDR); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_IP4_SRC_ADDR, PPE_FIELD_IP4_SRC_ADDR); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_L4_DST_PORT, PPE_FIELD_L4_DST_PORT); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_L4_SRC_PORT, PPE_FIELD_L4_SRC_PORT); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_IP4_PROTO, PPE_FIELD_IP4_PROTOCOL); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_IP4_TOS, PPE_FIELD_IP4_TOS); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ICMP_TYPE, PPE_FIELD_ICMP_TYPE); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ICMP_CODE, PPE_FIELD_ICMP_CODE); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_INGRESS_PORT, PPE_FIELD_META_INGRESS_PORT); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_PACKET_FORMAT, PPE_FIELD_META_PACKET_FORMAT); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ARP_SPA, PPE_FIELD_ARP_SPA); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ARP_TPA, PPE_FIELD_ARP_TPA); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ARP_PTYPE, PPE_FIELD_ARP_PTYPE); 
    ppe_field_copy(ppep, PPE_FIELD_OF10_ARP_OPERATION, PPE_FIELD_ARP_OPERATION); 

    /*
     * For OF 1.0 the ICMP type/code are in the L4 ports.
     * See LOXI-4.
     */
    if (key->keymask & (1<<PPE_HEADER_ICMP)) {
        key->keymask |= (1<<PPE_HEADER_L4);
        ppe_field_copy(ppep, PPE_FIELD_OF10_L4_SRC_PORT, PPE_FIELD_ICMP_TYPE);
        ppe_field_copy(ppep, PPE_FIELD_OF10_L4_DST_PORT, PPE_FIELD_ICMP_CODE);
    }
    
    return 0; 
}

/** \brief Process a received packet */

indigo_error_t
indigo_fwd_packet_receive(of_port_no_t of_port_num,
                          uint8_t      *data,
                          unsigned     len
                          )
{
    indigo_error_t       result = INDIGO_ERROR_NONE;
    ppe_packet_t         ppep; 
    int                  n, rv;
    fme_entry_t*         match_entry; 
    fme_key_t            fme_key; 
    struct fme_flow_data *fme_flow_data;
    of_list_action_t     *of_list_action;
    of_action_t          of_action[1];
    time_t               now;

    LOG_TRACE("%d bytes in from %d", len, of_port_num);

    if (INDIGO_FAILURE(ppe_pkt_setup(of_port_num,
                                     data,
                                     len,
                                     &ppep))) {
        LOG_ERROR("ppe_pkt_setup() failed");
        return (INDIGO_ERROR_UNKNOWN);
    }
    if (INDIGO_FAILURE(fme_key_setup(&ppep, &fme_key))) { 
        LOG_ERROR("fme_key_setup() failed"); 
        return (INDIGO_ERROR_UNKNOWN); 
    }

    ++lookup_count;

    time(&now);
    
    if (FME_FAILURE(n = fme_match(fme, 
                                  &fme_key, 
                                  expiration_enabled ? now : 0,
                                  ppep.size, 
                                  &match_entry))) { 
        LOG_ERROR("fme_match() failed."); 
        return (INDIGO_ERROR_UNKNOWN);
    }

    LOG_TRACE("FME returned %d for match on packet from %d", n, of_port_num); 
    if (n == 0) {
        if (INDIGO_FAILURE(result = pkt_in(&ppep,
                                           OF_PACKET_IN_REASON_NO_MATCH
                                           )
                           )
            ) {
            LOG_ERROR("pkt_in() failed");
        }
        return (result);
    }

    ++matched_count;

    fme_flow_data = (struct fme_flow_data *) (match_entry->cookie); 

    /* Update flow stats */

    ++fme_flow_data->cnt_pkts;
    fme_flow_data->cnt_bytes += len;
    
    /* Process actions given in flow that packet matched.
       \note The OF 1.0 spec says that in case of multiple matched flows of
       equal priority, the switch is free to choose which flow's actions will
       be applied, so we just use the first match; 
    */

    of_list_action = fme_flow_data->of_list_action;
    OF_LIST_ACTION_ITER(of_list_action, of_action, rv) {
        if (INDIGO_FAILURE(pkt_action_do(of_port_num,
                                         &ppep,
                                         of_action
                                         )
                           )
            ) {
            LOG_ERROR("pkt_action_do() failed");
            result = INDIGO_ERROR_UNKNOWN;
            break;
        }
    }
  
    ppe_packet_denit(&ppep); 
    return (result);
}


/**
 * Currently no experimenter messages supported in the fowarding module
 */

indigo_error_t
indigo_fwd_experimenter(of_experimenter_t *experimenter,
                        indigo_cxn_id_t cxn_id)
{
    LOG_TRACE("Forwarding experimenter called");

    return INDIGO_ERROR_NOT_SUPPORTED;    
}

/** \brief Handle packet out request from Core */

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    of_port_no_t     of_port_num;
    of_list_action_t *of_list_action = 0;
    of_action_t      of_action[1];
    of_octets_t      of_octets[1];
    ppe_packet_t     ppep; 
    int              rv;

    of_packet_out_in_port_get(of_packet_out, &of_port_num);
    of_packet_out_data_get(of_packet_out, of_octets);

    if (INDIGO_FAILURE(ppe_pkt_setup(of_port_num,
                                     of_octets->data,
                                     of_octets->bytes,
                                     &ppep
                                     )   
                       )
        ) {
        LOG_ERROR("ppe_pkt_setup() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    ++ind_fwd_packet_out_packets;
    ind_fwd_packet_out_bytes += of_octets->bytes;

    of_list_action = of_packet_out_actions_get(of_packet_out);

    if (of_list_action == NULL) {
        LOG_ERROR("of_packet_out_actions_get() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    OF_LIST_ACTION_ITER(of_list_action, of_action, rv) {
        if (INDIGO_FAILURE(pkt_action_do(of_port_num,
                                         &ppep,
                                         of_action
                                         ))) {
            LOG_ERROR("pkt_action_do() failed");
            result = INDIGO_ERROR_UNKNOWN;
            break;
        }
    }

    if (rv != OF_ERROR_NONE && rv != OF_ERROR_RANGE) {
        LOG_ERROR("of_list_action_first/next() failed");
        result = INDIGO_ERROR_UNKNOWN;
    }

 done:
    if (of_list_action)  of_list_action_delete(of_list_action);
  
    ppe_packet_denit(&ppep); 
    return (result);
}


/** \brief Intialize */

indigo_error_t
ind_fwd_init(ind_fwd_config_t *config)
{
    *my_config = *config;

    if (FME_FAILURE(fme_create(&fme, 
                              "flowman flow table",
                               my_config->max_flows))) { 
        LOG_ERROR("fme_create() failed");
        return (INDIGO_ERROR_UNKNOWN);
    }

    ind_cfg_register(&ind_fwd_cfg_ops);

    init_done = 1;

    return (INDIGO_ERROR_NONE);
}


indigo_error_t
ind_fwd_enable_set(int enable)
{
    module_enabled = enable;
    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_fwd_enable_get(int *enable)
{
    if (enable == NULL) {
        return INDIGO_ERROR_PARAM;
    }
    *enable = module_enabled;
    return INDIGO_ERROR_NONE;
}



/**
 * Notify forwarding of changes in expiration processing behavior
 */

indigo_error_t
indigo_fwd_expiration_enable_set(int is_enabled)
{
    LOG_TRACE("Setting fwd expiration enable to %d", is_enabled);
    expiration_enabled = is_enabled;

    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_expiration_enable_get(int *is_enabled)
{
    if (is_enabled == NULL) {
        return INDIGO_ERROR_PARAM;
    }

    *is_enabled = expiration_enabled;

    return INDIGO_ERROR_NONE;
}


/** \brief Tear down */

indigo_error_t
ind_fwd_finish(void)
{
    biglist_t *bl, *ble;
    int idx;
    struct fme_flow_data *p;

    /* Walk the FME table entries and delete the cookies */
    for (idx = 0; idx < FLOW_ID_HASH_TABLE_LEN; idx++) {
        bl = flow_id_ht[idx];

        BIGLIST_FOREACH(ble, bl) {
            p = BIGLIST_CAST(struct fme_flow_data *, ble);
            if (p->of_list_action) {
                of_list_action_delete(p->of_list_action);
            }
            INDIGO_MEM_FREE(p); 
        }       
        biglist_free(bl); 
    }
    
    fme_destroy_all(fme); 

    init_done = 0;

    return (INDIGO_ERROR_NONE);
}
