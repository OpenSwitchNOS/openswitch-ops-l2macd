/*
 *Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 *All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

/*************************************************************************//**
 * @ingroup l2macd
 *
 * @file
 * Main source file for the implementation of l2macd's OVSDB interface.
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dynamic-string.h>
#include <vswitch-idl.h>
#include <openswitch-idl.h>
#include <openvswitch/vlog.h>
#include <hash.h>
#include <shash.h>
#include "l2macd.h"
#include "poll-loop.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(l2macd_ovsdb_if);

struct vlan_data {
    struct hmap_node hmap_node;  /* In struct l2mac_table "vlans" hmap. */
    int vlan_id;                 /* VLAN ID */
    bool admin_state;           /* VLAN admin status */
    bool op_state;              /* VLAN operational status */
};

struct port_data {
    struct hmap_node hmap_node;     /* In struct l2mac_table "port" hmap. */
    char *name;                     /* Port name*/
    bool link_state;                /* Link status . */
};

/* L2MACD Internal data cache. */
struct l2macd_data_cache {
    struct hmap port_table;     /* Port table.cache */
    struct hmap vlan_table;     /* VLAN table cache */
};

struct ovsdb_idl *idl;
static unsigned int idl_seqno;

static int system_configured = false;

static struct l2macd_data_cache *g_l2macd_cache = NULL;

#define IS_CHANGED(x,y) (x != y)
#define MAC_FLUSH_TRY_AGAIN_MSEC 100

/* Create a connection to the OVSDB at db_path and create a DB cache
 * for this daemon. */
void
l2macd_ovsdb_init(const char *db_path)
{
    /* Initialize IDL through a new connection to the DB. */
    idl = ovsdb_idl_create(db_path, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ops_l2macd");

    /* Cache System table. */
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);

    /* Cache Interface table columns. */
    ovsdb_idl_add_table(idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_link_state);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_type);

    /* Cache Port table columns. */
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_vlan_mode);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_tag);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_trunks);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_macs_invalid);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_macs_invalid_on_vlans);

    /* Track port table columns. */
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_vlan_mode);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_tag);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_trunks);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_macs_invalid);
    ovsdb_idl_track_add_column(idl, &ovsrec_port_col_macs_invalid_on_vlans);

    /* Cache VLAN table columns. */
    ovsdb_idl_add_table(idl, &ovsrec_table_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_admin);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_oper_state);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_macs_invalid);

    /* Track VLAN table columns. */
    ovsdb_idl_track_add_column(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_track_add_column(idl, &ovsrec_vlan_col_admin);
    ovsdb_idl_track_add_column(idl, &ovsrec_vlan_col_oper_state);
    ovsdb_idl_track_add_column(idl, &ovsrec_vlan_col_macs_invalid);

    /* Cache MAC table columns. */
    ovsdb_idl_add_table(idl, &ovsrec_table_mac);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_mac_addr);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_tunnel_key);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_port);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_from);
    ovsdb_idl_add_column(idl, &ovsrec_mac_col_status);

    /* Track MAC table columns. */
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_mac_addr);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_bridge);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_tunnel_key);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_vlan);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_port);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_from);
    ovsdb_idl_track_add_column(idl, &ovsrec_mac_col_status);
} /* l2macd_ovsdb_init */

void
l2macd_mac_table_init(void)
{
    /* Allocate Memory */
    g_l2macd_cache = xmalloc(sizeof *g_l2macd_cache);

    hmap_init(&g_l2macd_cache->vlan_table);
    hmap_init(&g_l2macd_cache->port_table);
}   /* l2macd_mactable_init */

void
l2macd_ovsdb_exit(void)
{
    struct port_data *iface, *next_iface;
    struct vlan_data *vlan, *next_vlan;

    /* Free port table. */
    HMAP_FOR_EACH_SAFE (iface, next_iface, hmap_node,
                        &g_l2macd_cache->port_table) {
        free(iface);
    }

    /* Free vlan table.*/
    HMAP_FOR_EACH_SAFE (vlan, next_vlan, hmap_node,
                        &g_l2macd_cache->port_table) {
        free(vlan);
    }

    hmap_destroy(&g_l2macd_cache->vlan_table);
    hmap_destroy(&g_l2macd_cache->port_table);
    free(g_l2macd_cache);
    ovsdb_idl_destroy(idl);
} /* l2macd_ovsdb_exit */

static int
mac_flush_by_port(const struct ovsrec_port *port_row, bool port_delete)
{
    const struct ovsrec_mac *mac_row = NULL;
    struct ovsdb_idl_txn *txn = NULL;
    enum ovsdb_idl_txn_status status = TXN_SUCCESS;
    bool mac_invalid = true, retry = false;
    int rc = 0;

    txn = ovsdb_idl_txn_create(idl);

    /* TODO: Use OVSDB index based search to flush.mac entries */
    OVSREC_MAC_FOR_EACH(mac_row, idl)   {
        ovs_assert(mac_row->port);
        if (mac_row->port
            && !strcmp(mac_row->port->name, port_row->name)
            && !strcmp(mac_row->from, OVSREC_MAC_FROM_LEARNING))   {
            VLOG_DBG("%s: %s entry deleted %s \n",
                      __FUNCTION__,
                      port_row->name,
                      mac_row->mac_addr);
            /* Delete the MAC entries from the OVSDB. */
            ovsrec_mac_delete(mac_row);
            rc++;
        }
    }

    /*  Port row is deleted? */
    if  (port_delete == false)  {
        /* Set MAC flush request on this port, If no other requests pending.*/
        if (port_row->n_macs_invalid == 0
            || (port_row->macs_invalid
                && port_row->macs_invalid[0] == false))   {
            ovsrec_port_set_macs_invalid(port_row, &mac_invalid, 1);
            ovsrec_port_verify_macs_invalid(port_row);
            rc++;
            ovsdb_idl_txn_add_comment(txn, "l2macd-%s-flush", port_row->name);
        }   else {
            /* Already some requests pending try again. */
            retry = true;
            rc = 0;
        }
    }

    if (rc) {
        status = ovsdb_idl_txn_commit_block(txn);
        if (status == TXN_TRY_AGAIN)    {
            ovsdb_idl_txn_abort(txn);
            retry = true;
        }
    }

    if (retry) {
        /* Register timer event after 100ms to try again.*/
        poll_timer_wait_until(time_msec() + MAC_FLUSH_TRY_AGAIN_MSEC);
        rc = -1;
        VLOG_DBG("%s: flush port %s Try Again \n",
                  __FUNCTION__, port_row->name);
    }

    VLOG_DBG("%s: flush %s \n", __FUNCTION__, port_row->name);

    ovsdb_idl_txn_destroy(txn);
    return rc;
}/* mac_flush_by_port */

static bool
check_system_iface(const struct ovsrec_port *port)
{
    int i = 0;
    bool rc = false;

    for (i = 0; i < port->n_interfaces; i++) {
        const char *type = port->interfaces[i]->type;
        if (!strcmp(type, OVSREC_INTERFACE_TYPE_SYSTEM)) {
            rc = true;
        }
    }

    return rc;
}   /* check_system_iface */

static struct port_data *
port_lookup(const struct hmap* port_hmap, const char *name)
{
    struct port_data *local_port;

    HMAP_FOR_EACH_WITH_HASH (local_port, hmap_node, hash_string(name, 0),
                             port_hmap) {
        if (!strcmp(local_port->name, name)) {
            return local_port;
        }
    }

    return NULL;
}   /* port_lookup */

static void
update_port_data(const struct ovsrec_port *port_row,
                     struct port_data *port_data)
{
    int i = 0, rc = 0;
    bool link_up = false;
    bool flush = false;

    /* Make sure all the interfaces part of the logical port is down.*/
    for (i = 0; i < port_row->n_interfaces; i++) {
        struct ovsrec_interface *iface_row = port_row->interfaces[i];

        if (iface_row->link_state &&
            !strcmp(iface_row->link_state, OVSREC_INTERFACE_LINK_STATE_UP)) {
            link_up = true;
        }
    }

    if (IS_CHANGED(port_data->link_state, link_up)) {
        flush = true;
    }

    VLOG_DBG("%s: %s flush %d %d",
              __FUNCTION__,
              port_row->name, flush, link_up);

    /* Flush only link down cases */
    if (flush && !link_up){
         rc = mac_flush_by_port(port_row, false);
    }

    /* Update state changes only If OVSDB transaction completed successfully
     * If the status is TXN_TRY_AGAIN, will be retried after 100ms, so skip the
     * update state changes locally..
    */
    if  (rc >= 0) {
        port_data->link_state = link_up;
    }
}/* update_port_data */

static void
update_port(const struct ovsrec_port *port_row)
{
    struct port_data *port_data = NULL;

    /* Check interface table for valid physical interface */
    if (!check_system_iface(port_row))  {
       VLOG_DBG("%s: %s interface type is not system",
                 __FUNCTION__,
                 port_row->name);
       return;
    }

    port_data = port_lookup(&g_l2macd_cache->port_table, port_row->name);

    if (!port_data)  {
        port_data = xzalloc(sizeof *port_data);
        port_data->name = xstrdup(port_row->name);
        hmap_insert(&g_l2macd_cache->port_table, &port_data->hmap_node,
                    hash_string(port_row->name, 0));
        port_data->link_state= false;
    }

    update_port_data(port_row, port_data);

    VLOG_DBG("%s: %s added count %zu", __FUNCTION__,
              port_data->name, hmap_count(&g_l2macd_cache->port_table));
} /* add_new_port */

static void
del_old_port(const struct ovsrec_port *port_row)
{
    struct port_data *old_port = NULL;

    if (!(old_port = port_lookup(&g_l2macd_cache->port_table,
                     port_row->name)))  {
        VLOG_DBG("%s: name not found %s, hmap count %zu",
                 __FUNCTION__,
                 port_row->name,
                 hmap_count(&g_l2macd_cache->port_table));
        return;
    }

    mac_flush_by_port(port_row, true);

    hmap_remove(&g_l2macd_cache->port_table, &old_port->hmap_node);
    free(old_port->name);
    free(old_port);

    VLOG_DBG("%s: %s count %zu", __FUNCTION__,
              port_row->name, hmap_count(&g_l2macd_cache->port_table));
} /* del_old_port */

static void
update_port_cache(void)
{
    const struct ovsrec_port *port_row;
    const struct ovsrec_interface *interface_row;
    int track = 0, i = 0;
    unsigned int local_idl_seqno = 0;
    bool modified = false;

    local_idl_seqno = ovsdb_idl_get_seqno(idl);

    /* Track all the ports changes in the DB. */
    OVSREC_PORT_FOR_EACH_TRACKED(port_row, idl) {
        /* Add new ports to the cache. */
        if(ovsrec_port_row_get_seqno(port_row, OVSDB_IDL_CHANGE_INSERT)
                           >= local_idl_seqno)  {
            update_port(port_row);
            track++;
        }

        /* Delete ports from the cache. */
        if(ovsrec_port_row_get_seqno(port_row, OVSDB_IDL_CHANGE_DELETE)
                   >= local_idl_seqno)  {
            del_old_port(port_row);
            track++;
        }

        /* Update modified ports to the cache. */
        if(ovsrec_port_row_get_seqno(port_row, OVSDB_IDL_CHANGE_MODIFY)
                   >= local_idl_seqno)  {
            update_port(port_row);
            track++;
        }
    }

    port_row = ovsrec_port_first(idl);
    interface_row = ovsrec_interface_first(idl);

    /* Check any port table changes pending. */
    if (port_row
        && (OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(port_row, idl_seqno)
            || OVSREC_IDL_ANY_TABLE_ROWS_DELETED(port_row, idl_seqno)
            || OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(port_row, idl_seqno))) {
        modified = true;
    }

    /* Handle Interface table changes. */
    if (interface_row
        && (OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(interface_row, idl_seqno)
            || OVSREC_IDL_ANY_TABLE_ROWS_DELETED(interface_row, idl_seqno)
            || OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(interface_row, idl_seqno))) {
        modified = true;
    }

    if (modified == false)  {
        return;
    }

    /* Update port table cache for interface row changes also. */
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        /* Handle Interface changes */
        for (i = 0; i < port_row->n_interfaces; i++) {
            struct ovsrec_interface *iface_row = port_row->interfaces[i];
            if (OVSREC_IDL_IS_ROW_MODIFIED(iface_row, idl_seqno)) {
                update_port(port_row);
            }
        }
    }
} /* update_port_cache */

static int
mac_flush_by_vlan(const struct ovsrec_vlan *vlan_row, bool vlan_delete)
{
    const struct ovsrec_mac *mac_row = NULL;
    struct ovsdb_idl_txn *txn;
    bool mac_invalid = true, retry = false;
    int rc = 0;
    enum ovsdb_idl_txn_status status = TXN_SUCCESS;

    txn = ovsdb_idl_txn_create(idl);

    /* TODO: Use OVSDB index based search to flush. */
    OVSREC_MAC_FOR_EACH(mac_row, idl)   {
        if (mac_row->vlan == vlan_row->id &&
            !strcmp(mac_row->from, OVSREC_MAC_FROM_LEARNING))   {
            /* Delete the MAC entries from the OVSDB */
            VLOG_DBG("%s: entry deleted %s \n", __FUNCTION__,
                     mac_row->mac_addr);
            ovsrec_mac_delete(mac_row);
            rc++;
        }
    }

    if (vlan_delete == false)   {
        /* Set MAC flush request on this VLAN, If no other requests pending. */
        if (vlan_row->n_macs_invalid == 0
            || (vlan_row->macs_invalid
                && vlan_row->macs_invalid[0] == false)) {
            ovsrec_vlan_set_macs_invalid(vlan_row, &mac_invalid, 1);
            ovsrec_vlan_verify_macs_invalid(vlan_row);
            ovsdb_idl_txn_add_comment(txn, "l2macd-%ld-flush", vlan_row->id);
            rc++;
        }  else {
            /* Already some requests pending. */
            retry = true;
            rc = 0;
        }
    }

    if (rc) {
        status = ovsdb_idl_txn_commit_block(txn);
        /* Retry the transaction. */
        if (status == TXN_TRY_AGAIN)    {
            ovsdb_idl_txn_abort(txn);
            retry = true;
            VLOG_DBG("%s: vlan %ld Try Again \n", __FUNCTION__,
                     vlan_row->id);
        }
    }

    if (retry) {
        /* Register timer event after 100ms to try again.*/
        poll_timer_wait_until(time_msec() + MAC_FLUSH_TRY_AGAIN_MSEC);
        rc = -1;
        VLOG_DBG("%s: Retry already pending requests %ld \n",
                 __FUNCTION__, vlan_row->id);
    }

    ovsdb_idl_txn_destroy(txn);
    return rc;
}

static void
update_vlan_data(const struct ovsrec_vlan *row, struct vlan_data *vlan_ptr)
{
    bool admin_up = false, op_up = false;
    bool flush = false;
    int rc = 0;

    vlan_ptr->vlan_id = (int) row->id;

    /* Update admin_state to unknown. */
    if (row->admin &&
        !strcmp(OVSREC_VLAN_ADMIN_UP, row->admin)) {
        admin_up = true;
    }

    /* Update oper_state to unknown. */
    if (row->oper_state &&
        !strcmp(OVSREC_VLAN_OPER_STATE_UP, row->admin)) {
        op_up = true;
    }

    flush = IS_CHANGED(vlan_ptr->admin_state, admin_up);
    flush = IS_CHANGED(vlan_ptr->op_state, op_up);

    /* Flush only admin/operational down cases */
    if (flush && (!admin_up || !op_up))  {
        rc = mac_flush_by_vlan(row, false);
    }

    /* Update state changes only If OVSDB transaction completed successfully
     * If the status is TXN_TRY_AGAIN, will be retried after 100ms, so skip the
     * update state changes locally..
    */
    if  (rc >= 0) {
        vlan_ptr->admin_state = admin_up;
        vlan_ptr->op_state = op_up;
    }
} /* update_vlan_data */

static inline struct vlan_data *
vlan_lookup_by_vid(const struct hmap* vlan_hmap, int vid)
{
    struct vlan_data *vlan;

    HMAP_FOR_EACH (vlan, hmap_node, vlan_hmap) {
        if (vlan->vlan_id == vid) {
            return vlan;
        }
    }
    return NULL;
}

static void
update_vlan(const struct ovsrec_vlan *vlan_row)
{
    struct vlan_data *new_vlan = NULL;

    new_vlan = vlan_lookup_by_vid(&g_l2macd_cache->vlan_table,
                                  vlan_row->id);
    if(!new_vlan)  {
        /* Allocate structure to save state information for this VLAN. */
        new_vlan = xzalloc(sizeof(struct vlan_data));
        new_vlan->vlan_id = (int) vlan_row->id;
        new_vlan->admin_state= false;
        new_vlan->op_state= false;
        hmap_insert(&g_l2macd_cache->vlan_table, &new_vlan->hmap_node,
                        hash_int(vlan_row->id, 0));
    }

    /* Update VLAN configuration into internal format. */
    update_vlan_data(vlan_row, new_vlan);

    VLOG_DBG("%s: %d, hmap count %zu", __FUNCTION__, (int)vlan_row->id,
             hmap_count(&g_l2macd_cache->vlan_table));

} /* add_new_vlan */

static void
del_old_vlan(const struct ovsrec_vlan *vlan_row)
{
    struct vlan_data *old_vlan = NULL;

    old_vlan = vlan_lookup_by_vid(&g_l2macd_cache->vlan_table, vlan_row->id);

    if (!old_vlan) {
        VLOG_ERR("%s: %d, hmap count %zu",
                 __FUNCTION__,
                 (int)vlan_row->id,
                 hmap_count(&g_l2macd_cache->vlan_table));
        return;
    }

    mac_flush_by_vlan(vlan_row, true);

    hmap_remove(&g_l2macd_cache->vlan_table, &old_vlan->hmap_node);

    /* Free the VLAN data */
    free(old_vlan);

    VLOG_DBG("%s: %d, hmap count %zu", __FUNCTION__, (int)vlan_row->id,
              hmap_count(&g_l2macd_cache->vlan_table));
} /* del_old_vlan */

static void
update_vlan_cache(void)
{
    const struct ovsrec_vlan *vlan_row;
    int track = 0;
    unsigned int local_idl_seqno = 0;

    local_idl_seqno = ovsdb_idl_get_seqno(idl);

    /* Track all the VLAN changes in the DB. */
    OVSREC_VLAN_FOR_EACH_TRACKED(vlan_row, idl) {
        /* Add new VLAN to the cache */
        if(ovsrec_vlan_row_get_seqno(vlan_row, OVSDB_IDL_CHANGE_INSERT)
                           >= local_idl_seqno)  {
            update_vlan(vlan_row);
            track++;
        }

        /* Update modified VLAN to the cache */
        if(ovsrec_vlan_row_get_seqno(vlan_row, OVSDB_IDL_CHANGE_MODIFY)
                   >= local_idl_seqno)  {
            update_vlan(vlan_row);
            track++;
        }

        /* Delete VLAN from the cache */
        if(ovsrec_vlan_row_get_seqno(vlan_row, OVSDB_IDL_CHANGE_DELETE)
                   >= local_idl_seqno)  {
            del_old_vlan(vlan_row);
            track++;
        }
    }

    vlan_row = ovsrec_vlan_first(idl);

    /* Make sure its not a VLAN related changes. */
    if (vlan_row
        && (!OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(vlan_row, idl_seqno))
        && (!OVSREC_IDL_ANY_TABLE_ROWS_DELETED(vlan_row, idl_seqno))
        && (!OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(vlan_row, idl_seqno)))
    {
        return;
    }

    if (track) {
        return;
    }

    /* Update VLAN table cache */
    OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
        if (OVSREC_IDL_IS_ROW_INSERTED(vlan_row, idl_seqno) ||
            OVSREC_IDL_IS_ROW_MODIFIED(vlan_row, idl_seqno)) {
            update_vlan(vlan_row);
        }
    }

    return;
} /* update_vlan_cache */

static void
l2macd_reconfigure(void)
{
    unsigned int new_idl_seqno = ovsdb_idl_get_seqno(idl);

    if (new_idl_seqno == idl_seqno) {
        /* There was no change in the DB. */
        return;
    }

    /* Update Port table cache. */
    update_port_cache();

    /* Update VLAN table cache. */
    update_vlan_cache();

    /* Update IDL sequence # after we've handled everything. */
    idl_seqno = new_idl_seqno;

    /* Clear all the track */
    ovsdb_idl_track_clear(idl);
} /* l2macd_reconfigure */

static inline void
l2macd_chk_for_system_configured(void)
{
    const struct ovsrec_system *sys = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    sys = ovsrec_system_first(idl);

    if (sys && sys->cur_cfg > (int64_t) 0) {
        system_configured = true;
        VLOG_DBG("System is now configured (cur_cfg=%d).",
                  (int)sys->cur_cfg);
    }

} /* l2macd_chk_for_system_configured */

void
l2macd_run(void)
{
    /* Process a batch of messages from OVSDB. */
    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "Another l2macd process is running, "
                    "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        return;
    }

    /* Update the local configuration and push any changes to the DB.
     * Only do this after the system has been configured by CFGD, i.e.
     * table System "cur_cfg" > 1.
    */
    l2macd_chk_for_system_configured();
    if (system_configured) {
        l2macd_reconfigure();
    }

    return;
} /* l2macd_run */

void
l2macd_wait(void)
{
    ovsdb_idl_wait(idl);
} /* l2macd_wait */
