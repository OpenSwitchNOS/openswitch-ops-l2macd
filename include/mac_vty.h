/*
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
/****************************************************************************
 * @ingroup cli/vtysh
 *
 * @file mac_vty.h
 * To add declarations required for mac_vty.c
 *
 ***************************************************************************/

#ifndef _MAC_VTY_H
#define _MAC_VTY_H

#define MAC_AGE_TIME     300
#define MAX_VLAN_ID_SIZE 5

#define SHOW_MAC_TABLE_STR  "Show L2 MAC address table information\n"
#define SHOW_MAC_DYN_STR    "Show learnt MAC addresses\n"
#define SHOW_MAC_STATIC_STR "Show static MAC addresses\n"
#define SHOW_MAC_HWVTEP_STR "Show controller added MAC addresses\n"
#define SHOW_MAC_VLAN_STR   "Show MAC addresses learnt on VLAN(s)\n"
#define SHOW_MAC_PORT_STR   "Show MAC addresses learnt on port(s)\n"
#define SHOW_MAC_TUNNEL_STR "Show MAC addresses learnt on tunnel\n"
#define SHOW_MAC_ADDR_STR   "Show a specific MAC address\n"
#define MAC_VLAN_STR        "List of VLANs [e.g. 2,3-10]\n"
#define MAC_PORT_STR        "List of ports [e.g. 2-6,lag1]\n"
#define MAC_COUNT_STR       "Number of MAC addresses\n"

#define DISPLAY_MACTABLE_HEADER(vty, count)\
    vty_out (vty, "MAC age-time            : %d seconds%s", MAC_AGE_TIME, VTY_NEWLINE);\
    vty_out (vty, "Number of MAC addresses : %d%s", count, VTY_NEWLINE);\
    if (count) {\
        vty_out (vty, "\n%-20s %-8s %-10s %-10s%s", "MAC Address", "VLAN", "Type", "Port", VTY_NEWLINE);\
        vty_out (vty, "--------------------------------------------------%s", VTY_NEWLINE);\
    }\

#define DISPLAY_MACTABLE_ROW(vty, row, vlan_id) \
    vty_out(vty, "%-20s ", row->mac_addr);\
    vty_out(vty, "%-8s ",  vlan_id);\
    vty_out(vty, "%-10s ", row->from); \
    vty_out(vty, "%-10s ", row->port->name);\
    vty_out(vty, "%s", VTY_NEWLINE);\

#define DISPLAY_MACTABLE_COUNT(count)\
    vty_out (vty, "Number of MAC addresses : %d%s", count, VTY_NEWLINE);\

#endif
