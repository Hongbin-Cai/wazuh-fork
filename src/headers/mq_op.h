/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MQ_H
#define MQ_H

#include "config/localfile-config.h"

/* Default queues */
#define LOCALFILE_MQ    '1'
#define SYSLOG_MQ       '2'
#define HOSTINFO_MQ     '3'
#define SECURE_MQ       '4'
#define DBSYNC_MQ       '5'
#define SYSCHECK_MQ     '8'
#define ROOTCHECK_MQ    '9'
#define SCA_MQ          'p'


/* Queues for additional log types */
#define MYSQL_MQ         'a'
#define POSTGRESQL_MQ    'b'
#define AUTH_MQ          'c'
#define SYSCOLLECTOR_MQ  'd'
#define CISCAT_MQ        'e'
#define WIN_EVT_MQ       'f'

#define MAX_OPENQ_ATTEMPS 15

#define SEND_MSG_STR "Sending message from %s: '%s'"

// Component tags
#define LOGCOLLECTOR_TAG "Logcollector"
#define SYSCHECK_TAG "FIM"
#define SYSCOLLECTOR_TAG "Syscollector"
#define AZURE_TAG "Azure integration"
#define OSCAP_TAG "OpenSCAP integration"
#define VULNERABILITY_TAG "Vulnerability Detector"
#define AWS_TAG "AWS integration"
#define CISCAT_TAG "CIS-CAT integration"
#define OSQUERY_TAG "Osquery integration"
#define SCA_TAG "SCA"
#define COMMAND_TAG "Command"

extern int sock_fail_time;

int StartMQ(const char *key, short int type) __attribute__((nonnull));

int SendMSG(int queue, const char *message, const char *locmsg, char loc, char *tag) __attribute__((nonnull (2, 3)));

int SendMSGtoSCK(int queue, const char *message, const char *locmsg, char loc, logtarget *target, char *tag) __attribute__((nonnull (2, 3, 5)));

#endif /* MQ_H */
