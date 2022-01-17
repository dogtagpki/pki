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

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#ifdef __cplusplus
extern "C"
{
#endif

#include "nspr.h"
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "base64.h"
#include "nssb64.h"
#include "prlock.h"
#include "secder.h"
#include "cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "plstr.h"
#include "prmem.h"
#include "prprf.h"
#include "prtime.h"

#include "tus/tus_db.h"

static char *tokenActivityAttributes[] = { TOKEN_ID,
                                           TOKEN_CUID,
                                           TOKEN_OP,
                                           TOKEN_USER,
                                           TOKEN_MSG,
                                           TOKEN_RESULT,
                                           TOKEN_IP,
                                           TOKEN_C_DATE,
                                           TOKEN_M_DATE,
                                           TOKEN_TYPE,
                                           NULL };
static char *tokenAttributes[] = { TOKEN_ID,
                                   TOKEN_USER,
                                   TOKEN_STATUS,
                                   TOKEN_APPLET,
                                   TOKEN_KEY_INFO,
                                   TOKEN_MODS,
                                   TOKEN_C_DATE,
                                   TOKEN_M_DATE,
                                   TOKEN_RESETS,
                                   TOKEN_ENROLLMENTS,
                                   TOKEN_RENEWALS,
                                   TOKEN_RECOVERIES,
                                   TOKEN_POLICY,
                                   TOKEN_REASON,
                                   TOKEN_TYPE,
                                   NULL };
static char *tokenCertificateAttributes[] = { TOKEN_ID,
                                              TOKEN_CUID,
                                              TOKEN_USER,
                                              TOKEN_STATUS, 
                                              TOKEN_C_DATE,
                                              TOKEN_M_DATE,
                                              TOKEN_SUBJECT,
                                              TOKEN_ISSUER,
                                              TOKEN_SERIAL,
                                              TOKEN_CERT,
                                              TOKEN_TYPE,
                                              TOKEN_NOT_BEFORE,
                                              TOKEN_NOT_AFTER,
                                              TOKEN_KEY_TYPE,
                                              TOKEN_STATUS,
                                              NULL };

static char *userAttributes[] = {USER_ID,
                                 USER_SN,
                                 USER_GIVENNAME, 
                                 USER_CN, 
                                 USER_CERT, 
                                 C_TIME, 
                                 M_TIME, 
                                 PROFILE_ID,
                                 NULL};                                    

static char *viewUserAttributes[] = {USER_ID,
                                     USER_SN, 
                                     USER_CN, 
                                     C_TIME, 
                                     M_TIME, 
                                     NULL}; 
                                   
static char *tokenStates[] = { STATE_UNINITIALIZED,
                               STATE_ACTIVE,
                               STATE_DISABLED,
                               NULL };

#ifdef __cplusplus
}
#endif

static char *ssl     = NULL; /* true or false */
static char *host     = NULL;
static int  port      = 0;
static char *userBaseDN   = NULL;
static char *baseDN   = NULL;
static char *activityBaseDN   = NULL;
static char *certBaseDN   = NULL;
static char *bindDN   = NULL;
static char *bindPass = NULL;
static char *defaultPolicy = NULL;

static int  ccHost        = 0;
static int  ccBaseDN      = 0;
static int  ccBindDN      = 0;
static int  ccBindPass    = 0;

static LDAP *ld           = NULL;
static int  bindStatus    = -1;

TPS_PUBLIC int valid_berval(struct berval **b)
{
    if ((b != NULL) && (b[0] != NULL) && (b[0]->bv_val != NULL))
        return 1;
    return 0;
}

int free_results (LDAPMessage *results)
{
    return ldap_msgfree (results);
}

LDAPMessage *get_first_entry (LDAPMessage *result)
{
    return ldap_first_entry (ld, result);
}

LDAPMessage *get_next_entry (LDAPMessage *entry)
{
    return ldap_next_entry (ld, entry);
}

TPS_PUBLIC char **get_token_states()
{
    return tokenStates;
}

TPS_PUBLIC char **get_certificate_attributes()
{
    return tokenCertificateAttributes;
}

TPS_PUBLIC char **get_activity_attributes()
{
    return tokenActivityAttributes;
}

TPS_PUBLIC char **get_token_attributes()
{
    return tokenAttributes;
}

TPS_PUBLIC char **get_user_attributes()
{
    return userAttributes;
}

TPS_PUBLIC char **get_view_user_attributes()
{
    return viewUserAttributes;
}

TPS_PUBLIC char *get_token_users_name()
{
    return tokenAttributes[I_TOKEN_USER];
}

struct berval **get_token_users(LDAPMessage *entry)
{
    return ldap_get_values_len(ld, entry, TOKEN_USER);
}

char *get_token_id_name()
{
    return tokenAttributes[I_TOKEN_ID];
}

char *get_cert_attr_byname(LDAPMessage *entry, const char *name)
{
    struct berval **v = NULL;
    char *value = NULL;

    if (entry == NULL) return NULL;

    v = ldap_get_values_len(ld, entry, name);
    if (v == NULL) return NULL;
    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
        value = PL_strdup(v[0]->bv_val);
    }
    if( v != NULL ) {
        ldap_value_free_len( v );
        v = NULL;
    }

    return value;
}

int get_cert_attr_byname_int(LDAPMessage *entry, const char *name)
{
    struct berval **v = NULL;
    int  n = 0;

    if (entry == NULL) return 0;

    v = ldap_get_values_len(ld, entry, name);
    if (v == NULL) return 0;
    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
        n = atoi(v[0]->bv_val);
    }
    if( v != NULL ) {
        ldap_value_free_len( v );
        v = NULL;
    }

    return n;
}


char *get_token_id(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_ID);
}

char *get_cert_tokenType(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenType");
}

char *get_token_status_name()
{
    return tokenAttributes[I_TOKEN_STATUS];
}

TPS_PUBLIC char *get_reason_name()
{
    return tokenAttributes[I_TOKEN_REASON];
}

TPS_PUBLIC char *get_policy_name()
{
    return tokenAttributes[I_TOKEN_POLICY];
}

char *get_token_status(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_STATUS);
}

char *get_applet_id_name()
{
    return tokenAttributes[I_TOKEN_APPLET];
}

char *get_applet_id(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_APPLET);
}

char *get_key_info_name()
{
    return tokenAttributes[I_TOKEN_KEY_INFO];
}

char *get_key_info(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_KEY_INFO);
}

char *get_creation_date_name()
{
    return tokenAttributes[I_TOKEN_C_DATE];
}

char *get_creation_date(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_C_DATE);
}

char *get_modification_date_name()
{
    return tokenAttributes[I_TOKEN_M_DATE];
}

char *get_modification_date(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_M_DATE);
}

TPS_PUBLIC char *get_dn(LDAPMessage *entry)
{
    char *ret = NULL;
    char *dn = NULL;
    if ((dn = ldap_get_dn( ld, entry )) != NULL) {
        ret = PL_strdup(dn);
        ldap_memfree(dn);
    }
    return ret;
}
