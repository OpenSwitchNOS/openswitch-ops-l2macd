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

/************************************************************************//**
 * @defgroup ops-l2macd L2 MAC Daemon
 * This module is the OpenSwitch daemon that manages L2 MAC table in an
 * OpenSwitch switch.
 * @{
 *
 * @defgroup l2macd_public Public Interface
 * Public API for the OpenSwitch L2 MAC daemon (ops-l2macd)
 *
 * ops-l2macd is responsible for managing L2 MAC entries stored
 * in OVSDB.  In OpenSwitch L2 MAC entries are learned from the ASIC
 * and populated to OVSDB by vswitchd daemon.There is no way to explicitly
 * flush learned L2 MAC entires from the OVSDB based on the various modules
 * state changes, Instead of monitor various modules in the vswitchd context,
 * This l2macd daemon will montior configuration changes and flush mac entries
 * from the OVSDB and it informs vswitchd to flush those entries from the ASIC
 * L2 MAC table
 *
 *
 * Public APIs
 *
 *     ops-l2macd: OpenSwitch L2 MAC daemon
 *     usage: ops-l2macd [OPTIONS] [DATABASE]
 *     where DATABASE is a socket on which ovsdb-server is listening
 *           (default: "unix:/var/run/openvswitch/db.sock").
 *
 *     Daemon options:
 *       --detach                run in background as daemon
 *       --no-chdir              do not chdir to '/'
 *       --pidfile[=FILE]        create pidfile (default: /var/run/openvswitch/ops-l2macd.pid)
 *       --overwrite-pidfile     with --pidfile, start even if already running
 *
 *     Logging options:
 *       -vSPEC, --verbose=SPEC   set logging levels
 *       -v, --verbose            set maximum verbosity level
 *       --log-file[=FILE]        enable logging to specified FILE
 *                                (default: /var/log/openvswitch/ops-l2macd.log)
 *       --syslog-target=HOST:PORT  also send syslog msgs to HOST:PORT via UDP
 *
 *     Other options:
 *       --unixctl=SOCKET        override default control socket name
 *       -h, --help              display this help message
 *
 *
 * Available ovs-apptcl command options are:
 *
 *      coverage/show
 *      exit
 *      list-commands
 *      version
 *      ops-l2macd/dump
 *      vlog/disable-rate-limit [module]...
 *      vlog/enable-rate-limit  [module]...
 *      vlog/list
 *      vlog/reopen
 *      vlog/set                {spec | PATTERN:destination:pattern}
 *
 *
 * OVSDB elements usage
 *
 *  The following columns are READ by ops-l2macd:
 *
 *      System:cur_cfg
 *      Interface:name
 *      Interface:link_state
 *      Interface:type
 *      Port:name
 *      Port:vlan_mode
 *      Port:tag
 *      Port:interfaces
 *      VLAN:name
 *      VLAN:id
 *      VLAN:admin
 *      VLAN:oper_state
 *  The following columns are WRITTEN by ops-l2macd:
 *      Port:mac_invalid
 *      Port:mac_invalid_on_vlans
 *      VLAN:macs_invalid
 *
 * Linux Files:
 *
 *  The following files are written by ops-l2macd
 *
 *      /var/run/openvswitch/ops-l2macd.pid: Process ID for ops-l2macd
 *      /var/run/openvswitch/ops-l2macd.<pid>.ctl: Control file for ovs-appctl
 *
 * @{
 *
 * @file
 * Header for OpenSwitch L2 MAC daemon
 ***************************************************************************/

/** @} end of group l2macd_public */

#ifndef __L2MACD_H__
#define __L2MACD_H__

#include <dynamic-string.h>

/**************************************************************************//**
 * @details This function is called by the ops-l2macd main loop for processing
 * OVSDB change notifications. It will handle any Interface/VLAN/Port configuration
 * changes, Based on the changes it will flush the MAC entries from OVSDB MAC table.
 * & Updates the vswitchd to flush the MAC entries from ASIC
 * the OVSDB.
 *****************************************************************************/
extern void l2macd_run(void);

/**************************************************************************//**
 * @details This function is called by the ops-l2macd main loop to wait for
 * any OVSDB IDL processing.
 *****************************************************************************/
extern void l2macd_wait(void);

/**************************************************************************//**
 * @details This function is called during ops-l2macd start up to initialize
 * the OVSDB IDL interface and cache all necessary tables & columns.
 *
 * @param[in] db_path - name of the OVSDB socket path.
 *****************************************************************************/
extern void l2macd_ovsdb_init(const char *db_path);

/**************************************************************************//**
 * @details This function is called during ops-l2macd start up to initialize
 * the global l2 mac table hash map.
 *****************************************************************************/
extern void l2macd_mac_table_init(void);


/**************************************************************************//**
 * @details This function is called during ops-l2macd shutdown to free
 * any data structures & disconnect from the OVSDB IDL interface.
 *****************************************************************************/
extern void l2macd_ovsdb_exit(void);

/**************************************************************************//**
 * @details This function is called when user invokes ovs-appctl "ops-l2macd/dump"
 * command.  Prints all ops-l2macd debug dump information to the console.
 *
 * @param[in] ds - dynamic string into which the output data is written.
 *****************************************************************************/
extern void l2macd_debug_dump(struct ds *ds);
#endif /* __L2MACD_H__ */

/** @} end of group ops-l2macd */
