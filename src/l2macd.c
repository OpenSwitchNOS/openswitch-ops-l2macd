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
 * @ingroup ops-l2macd
 *
 * @file
 * Main source file for the implementation of the OpenSwitch L2 MAC table managing daemon.
 *
 *   1. During start up, read Interface, Port and VLAN related configuration
 *      data
 *
 *   2. Dynamically based on configuration changes initiates L2 MAC entries from OVSDB
 *
 *   3. Updates ops-switchd to flush the L2 MAC table entries from the ASIC by updating the
 *      Mac_flush_table.
 *
 ****************************************************************************/
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <config.h>
#include <command-line.h>
#include <compiler.h>
#include <daemon.h>
#include <dirs.h>
#include <dynamic-string.h>
#include <fatal-signal.h>
#include <ovsdb-idl.h>
#include <poll-loop.h>
#include <unixctl.h>
#include <util.h>
#include <openvswitch/vconn.h>
#include <openvswitch/vlog.h>
#include <vswitch-idl.h>
#include <openswitch-idl.h>
#include <hash.h>
#include <shash.h>

#include "l2macd.h"
VLOG_DEFINE_THIS_MODULE(ops_l2macd);

#define L2MACD_PID_FILE        "/var/run/openvswitch/ops-l2macd.pid"

/*-----------------------------------------------------------------------------
 | Function: l2macd_unixctl_dump
 | Responsibility: To dump the l2macd
 | Parameters:
 |      conn : unix socket to reply
 |      argc : number of arguments
 |      argv : arguments list
 |      aux : auxiliary parameters
 | Return:
 |      None
 ------------------------------------------------------------------------------
 */
static void
l2macd_unixctl_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    /* TODO: add dump functions */

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

} /* l2macd_unixctl_dump */

/*-----------------------------------------------------------------------------
 | Function: l2macd_init
 | Responsibility: l2macd initialize function
 | Parameters:
 |      db_path : ovsdb path
 | Return:
 |      None
 ------------------------------------------------------------------------------
 */
static void
l2macd_init(const char *db_path)
{
    /* Initialize IDL through a new connection to the DB. */
    l2macd_ovsdb_init(db_path);

    /* Initialize the global Internal cache table */
    l2macd_cache_init();

    /* Register ovs-appctl commands for this daemon. */
    unixctl_command_register("ops-l2macd/dump", "", 0, 0, l2macd_unixctl_dump, NULL);

} /* l2macd_init */

/*-----------------------------------------------------------------------------
 | Function: l2macd_exit
 | Responsibility: l2macd exit function
 | Parameters:
 |      None
 | Return:
 |      None
 ------------------------------------------------------------------------------
 */
static void
l2macd_exit(void)
{
    l2macd_ovsdb_exit();

} /* l2macd_exit */

static void
usage(void)
{
    printf("%s: OpenSwitch L2 MAC daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
    exit(EXIT_SUCCESS);

} /* usage */

/*-----------------------------------------------------------------------------
 | Function: parse_options
 | Responsibility: parsing the input arguments
 | Parameters:
 |      argc : arguments count
 |      argv : arguments list
 |      unixctl_pathp : db path
 | Return:
 |      pointer
 ------------------------------------------------------------------------------
 */

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }

} /* parse_options */

static void
l2macd_unixctl_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);

} /* l2macd_unixctl_exit */

int
main(int argc, char *argv[])
{
    char *appctl_path = NULL;
    struct unixctl_server *appctl;
    char *ovsdb_sock;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    fatal_ignore_sigpipe();

    /* Parse commandline args and get the name of the OVSDB socket. */
    ovsdb_sock = parse_options(argc, argv, &appctl_path);

    /* Initialize the metadata for the IDL cache. */
    ovsrec_init();

    /* Fork and return in child process; but don't notify parent of
     * startup completion yet. */
    daemonize_start();

    /* Create UDS connection for ovs-appctl. */
    retval = unixctl_server_create(appctl_path, &appctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    /* Register the ovs-appctl "exit" command for this daemon. */
    unixctl_command_register("exit", "", 0, 0, l2macd_unixctl_exit, &exiting);

    /* Create the IDL cache of the DB at ovsdb_sock. */
    l2macd_init(ovsdb_sock);
    free(ovsdb_sock);

    /* Notify parent of startup completion. */
    daemonize_complete();

    /* Enable asynch log writes to disk. */
    vlog_enable_async();

    VLOG_INFO_ONCE("%s (OpenSwitch L2 MAC Daemon) started", program_name);

    exiting = false;
    while (!exiting) {
        l2macd_run();
        unixctl_server_run(appctl);

        l2macd_wait();
        unixctl_server_wait(appctl);
        if (exiting) {
            poll_immediate_wake();
        } else {
            poll_block();
        }
    }

    l2macd_exit();
    unixctl_server_destroy(appctl);

    VLOG_INFO("%s (OpenSwitch L2 MAC Daemon) exiting", program_name);

    return 0;

} /* main */
