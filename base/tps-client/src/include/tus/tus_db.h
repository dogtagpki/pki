/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef TUS_DB_H
#define TUS_DB_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#include "ldap.h"
#include "lber.h"
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "base64.h"
#include "nssb64.h"
#include "prlock.h"

#define I_TOKEN_ID          0
#define TOKEN_ID            "cn"
#define I_TOKEN_USER        1
#define TOKEN_USER          "tokenUserID"
#define I_TOKEN_STATUS      2
#define TOKEN_STATUS        "tokenStatus"
#define I_TOKEN_APPLET      3
#define TOKEN_APPLET        "tokenAppletID"
#define I_TOKEN_KEY_INFO    4
#define TOKEN_KEY_INFO      "keyInfo"
#define I_TOKEN_MODS        5
#define TOKEN_MODS          "modified"
#define I_TOKEN_C_DATE      6
#define TOKEN_C_DATE        "dateOfCreate"
#define I_TOKEN_M_DATE      7
#define TOKEN_M_DATE        "dateOfModify"
#define I_TOKEN_RESETS      8
#define TOKEN_RESETS        "numberOfResets"
#define I_TOKEN_ENROLLMENTS 9
#define TOKEN_ENROLLMENTS   "numberOfEnrollments"
#define I_TOKEN_RENEWALS    10
#define TOKEN_RENEWALS      "numberOfRenewals"
#define I_TOKEN_RECOVERIES  11
#define TOKEN_RECOVERIES    "numberOfRecoveries"
#define I_TOKEN_POLICY  12
#define TOKEN_POLICY    "tokenPolicy"

#define I_TOKEN_CUID         13
#define TOKEN_CUID           "tokenID"
#define I_TOKEN_OP           14
#define TOKEN_OP             "tokenOp"
#define I_TOKEN_MSG          15
#define TOKEN_MSG            "tokenMsg"
#define I_TOKEN_RESULT          16
#define TOKEN_RESULT            "tokenResult"
#define I_TOKEN_IP          17
#define TOKEN_IP            "tokenIP"
#define I_TOKEN_CERT         18
#define TOKEN_CERT           "userCertificate"
#define I_TOKEN_SUBJECT      19
#define TOKEN_SUBJECT         "tokenSubject"
#define I_TOKEN_ISSUER       20 
#define TOKEN_ISSUER         "tokenIssuer"
#define I_TOKEN_ORIGIN       21 
#define TOKEN_ORIGIN         "tokenOrigin"
#define I_TOKEN_SERIAL       22 
#define TOKEN_SERIAL         "tokenSerial"
#define I_TOKEN_TYPE       23 
#define TOKEN_TYPE         "tokenType"
#define I_TOKEN_KEY_TYPE       24 
#define TOKEN_KEY_TYPE         "tokenKeyType"
#define I_TOKEN_REASON       13 
#define TOKEN_REASON         "tokenReason"
#define I_TOKEN_NOT_BEFORE       26 
#define TOKEN_NOT_BEFORE         "tokenNotBefore"
#define I_TOKEN_NOT_AFTER       27 
#define TOKEN_NOT_AFTER         "tokenNotAfter"
 
#define I_STATE_UNINITIALIZED 0
#define STATE_UNINITIALIZED   "uninitialized"
#define I_STATE_ACTIVE      1
#define STATE_ACTIVE        "active"
#define I_STATE_DISABLED    2
#define STATE_DISABLED      "disabled"
#define I_STATE_LOST        3
#define STATE_LOST          "lost"

#define C_TIME              "createTimeStamp"
#define M_TIME              "modifyTimeStamp"
#define USER_ID             "uid"
#define USER_PASSWORD       "userPassword"
#define USER_SN             "sn"
#define USER_CN             "cn"
#define USER_GIVENNAME      "givenName"
#define USER_CERT           "userCertificate"
#define PROFILE_ID          "profileID"
#define GROUP_MEMBER        "member"
#define SUBGROUP_ID         "cn"

/* roles */
#define OPERATOR            "Operators"
#define AGENT               "Agents"
#define ADMINISTRATOR       "Administrators"
#define MAX_RETRIES         2

#define ALL_PROFILES        "All Profiles"
#define NO_PROFILES         "NO_PROFILES"
#define NO_TOKEN_TYPE       "no_token_type"

TPS_PUBLIC int free_results (LDAPMessage *results);

TPS_PUBLIC LDAPMessage *get_first_entry (LDAPMessage *result);
TPS_PUBLIC LDAPMessage *get_next_entry (LDAPMessage *entry);

TPS_PUBLIC char **get_token_states();
TPS_PUBLIC char **get_token_attributes();
TPS_PUBLIC char **get_activity_attributes();
TPS_PUBLIC char **get_user_attributes();
TPS_PUBLIC char **get_view_user_attributes();
TPS_PUBLIC char *get_policy_name();
TPS_PUBLIC char *get_reason_name();
TPS_PUBLIC char **get_certificate_attributes();

TPS_PUBLIC char *get_token_users_name();
TPS_PUBLIC char *get_token_id_name();
TPS_PUBLIC char *get_token_status_name();
TPS_PUBLIC char *get_applet_id_name();
TPS_PUBLIC char *get_key_info_name();
TPS_PUBLIC char *get_creation_date_name();
TPS_PUBLIC char *get_modification_date_name();
#endif /* TUS_DB_H */
