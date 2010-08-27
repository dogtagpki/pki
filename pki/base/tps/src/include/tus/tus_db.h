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
#include "ldap_ssl.h"
#include "ldappr.h"
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
#define OPERATOR            "Officers"
#define AGENT               "Agents"
#define ADMINISTRATOR       "Administrators"
#define MAX_RETRIES         2

#define ALL_PROFILES        "All Profiles"
#define NO_PROFILES         "NO_PROFILES"
#define NO_TOKEN_TYPE       "no_token_type"

TPS_PUBLIC void set_tus_db_port(int number);
TPS_PUBLIC void set_tus_db_host(char *name);
TPS_PUBLIC void set_tus_db_baseDN(char *dn);
TPS_PUBLIC void set_tus_db_bindDN(char *dn);
TPS_PUBLIC void set_tus_db_bindPass(char *p);

TPS_PUBLIC int is_tus_db_initialized();
TPS_PUBLIC int get_tus_db_config(char *name);
TPS_PUBLIC int tus_db_init(char **errorMsg);
TPS_PUBLIC int allow_token_reenroll(char *cn);
TPS_PUBLIC int allow_token_renew(char *cn);
TPS_PUBLIC int force_token_format(char *cn);
TPS_PUBLIC int is_token_pin_resetable(char *cn);
TPS_PUBLIC int is_update_pin_resetable_policy(char *cn);
TPS_PUBLIC int is_token_present(char *cn);
TPS_PUBLIC int update_token_policy (char *cn, char *policy);
TPS_PUBLIC char *get_token_policy (char *cn);
TPS_PUBLIC char *get_token_userid(char *cn);
TPS_PUBLIC void tus_db_end();
TPS_PUBLIC void tus_db_cleanup();
TPS_PUBLIC void tus_print_as_hex(char *out, SECItem *data);
TPS_PUBLIC void tus_print_integer(char *out, SECItem *data);
TPS_PUBLIC int is_tus_db_entry_disabled(char *cn);
TPS_PUBLIC int add_default_tus_db_entry (const char *uid, const char *agentid, char *cn, const char *status, char *applet_version, char *key_info, const char *token_type );
TPS_PUBLIC int delete_tus_db_entry (char *userid, char *cn);
TPS_PUBLIC int find_tus_db_entry (char *cn, int max, LDAPMessage **result);
TPS_PUBLIC int find_tus_db_entries (const char *filter, int max, LDAPMessage **result);
TPS_PUBLIC int find_tus_token_entries (char *filter, int max, LDAPMessage **result, int order);
TPS_PUBLIC int find_tus_token_entries_no_vlv (char *filter, LDAPMessage **result, int order);
TPS_PUBLIC int tus_has_active_tokens(char *userid);
TPS_PUBLIC char *get_token_reason(LDAPMessage *e);

TPS_PUBLIC int update_tus_db_entry (const char *agentid,
                        char *cn, const char *uid, char *keyInfo,
                        const char *status,
                        char *applet_version, const char *reason);
TPS_PUBLIC int update_tus_db_entry_with_mods (const char *agentid, const char *cn, LDAPMod **mods);
TPS_PUBLIC int check_and_modify_tus_db_entry (char *userid, char *cn, char *check, LDAPMod **mods);
TPS_PUBLIC int modify_tus_db_entry (char *userid, char *cn, LDAPMod **mods);
TPS_PUBLIC int add_activity (char *ip, char *id, const char *op, const char *result, const char *msg, const char *userid, const char *token_type);
TPS_PUBLIC int find_tus_certificate_entries_by_order_no_vlv (char *filter,
  LDAPMessage **result, int order);
TPS_PUBLIC int find_tus_certificate_entries_by_order (char *filter, int max,
  LDAPMessage **result, int order);
TPS_PUBLIC int add_certificate (char *tokenid, char *origin, char *tokenType, char *userid, CERTCertificate *certificate, char *ktype, const char *status);
TPS_PUBLIC int add_tus_db_entry (char *cn, LDAPMod **mods);
TPS_PUBLIC int add_new_tus_db_entry (const char *userid, char *cn, const char *uid, int flag, const char *status, char *applet_version, char *key_info, const char *token_type);
TPS_PUBLIC int find_tus_activity_entries (char *filter, int max, LDAPMessage **result);
TPS_PUBLIC int find_tus_activity_entries_no_vlv (char *filter, LDAPMessage **result, int order);
TPS_PUBLIC int get_number_of_entries (LDAPMessage *result);
TPS_PUBLIC int free_results (LDAPMessage *results);

TPS_PUBLIC LDAPMessage *get_first_entry (LDAPMessage *result);
TPS_PUBLIC LDAPMessage *get_next_entry (LDAPMessage *entry);
TPS_PUBLIC CERTCertificate **get_certificates(LDAPMessage *entry);

TPS_PUBLIC char **get_token_states();
TPS_PUBLIC char **get_token_attributes();
TPS_PUBLIC char **get_activity_attributes();
TPS_PUBLIC char **get_user_attributes();
TPS_PUBLIC char **get_view_user_attributes();
TPS_PUBLIC char **get_attribute_values(LDAPMessage *entry, const char *attribute);
TPS_PUBLIC void free_values(char **values, int ldapValues);
TPS_PUBLIC char **get_token_users(LDAPMessage *entry);
TPS_PUBLIC char *get_token_id(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_tokenType(LDAPMessage *entry);
TPS_PUBLIC char *get_token_status(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_cn(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_status(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_type(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_serial(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_issuer(LDAPMessage *entry);
TPS_PUBLIC char *get_cert_attr_byname(LDAPMessage *entry, char *name);
TPS_PUBLIC char *get_applet_id(LDAPMessage *entry);
TPS_PUBLIC char *get_key_info(LDAPMessage *entry);
TPS_PUBLIC char *get_creation_date(LDAPMessage *entry);
TPS_PUBLIC char *get_modification_date(LDAPMessage *entry);
TPS_PUBLIC char *get_policy_name();
TPS_PUBLIC char *get_reason_name();
int find_tus_certificate_entries (char *filter, int max, LDAPMessage **result);
TPS_PUBLIC char **get_certificate_attributes();

TPS_PUBLIC int get_number_of_modifications(LDAPMessage *entry);
TPS_PUBLIC int get_number_of_resets(LDAPMessage *entry);
TPS_PUBLIC int get_number_of_enrollments(LDAPMessage *entry);
TPS_PUBLIC int get_number_of_renewals(LDAPMessage *entry);
TPS_PUBLIC int get_number_of_recoveries(LDAPMessage *entry);

TPS_PUBLIC char *get_token_users_name();
TPS_PUBLIC char *get_token_id_name();
TPS_PUBLIC char *get_token_status_name();
TPS_PUBLIC char *get_applet_id_name();
TPS_PUBLIC char *get_key_info_name();
TPS_PUBLIC char *get_creation_date_name();
TPS_PUBLIC char *get_modification_date_name();
TPS_PUBLIC char *get_number_of_modifications_name();
TPS_PUBLIC char *get_number_of_resets_name();
TPS_PUBLIC char *get_number_of_enrollments_name();
TPS_PUBLIC char *get_number_of_renewals_name();
TPS_PUBLIC char *get_number_of_recoveries_name();
TPS_PUBLIC char *get_dn(LDAPMessage *entry);

TPS_PUBLIC LDAPMod **allocate_modifications(int size);
TPS_PUBLIC void free_modifications(LDAPMod **mods, int ldapValues);
TPS_PUBLIC char **allocate_values(int size, int extra);
TPS_PUBLIC char **create_modification_date_change();
TPS_PUBLIC int base64_decode(char *src, unsigned char *dst);
TPS_PUBLIC char *tus_authenticate(char *cert);
TPS_PUBLIC int tus_authorize(const char *group, const char *userid);
TPS_PUBLIC int update_cert_status(char *cn, const char *status);
TPS_PUBLIC int update_token_status_reason(char *userid, char *cuid, 
  const char *tokenStatus, const char *reason);
TPS_PUBLIC int update_token_status_reason_userid(const char *userid, char *cuid,
  const char *tokenStatus, const char *reason, int modifyDateOfCreate);

TPS_PUBLIC int add_user_db_entry(const char *agentid, char *userid, char *userPassword, char *sn, char *givenName, char *cn, char * userCert);
TPS_PUBLIC int find_tus_user_entries_no_vlv(char *filter, LDAPMessage **result, int order);
TPS_PUBLIC int update_user_db_entry(const char *agentid, char *uid, char *lastName, char *givenName, char *userCN, char *userCert);
TPS_PUBLIC int add_profile_to_user(const char *agentid, char *userid, const char *profile);
TPS_PUBLIC int delete_profile_from_user(const char *agentid, char *userid, const char *profile);
TPS_PUBLIC int add_user_to_role_db_entry(const char *agentid, char *userid, const char *role);
TPS_PUBLIC int delete_user_from_role_db_entry(const char *agentid, char *userid, const char *role);
TPS_PUBLIC int find_tus_user_role_entries( const char*uid, LDAPMessage **result);
TPS_PUBLIC char *get_authorized_profiles(const char *userid, int is_admin);
TPS_PUBLIC int delete_user_db_entry(const char *agentid, char *uid);
TPS_PUBLIC int delete_all_profiles_from_user(const char *agentid, char *userid);
#endif /* TUS_DB_H */
