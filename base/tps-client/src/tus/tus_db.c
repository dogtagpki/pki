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

static PRFileDesc *debug_fd  = NULL;
static PRFileDesc *audit_fd  = NULL;

extern void audit_log(const char *func_name, const char *userid, const char *msg);

char *get_pwd_from_conf(char *filepath, char *name);
static int tus_check_conn();

TPS_PUBLIC int valid_berval(struct berval **b)
{
    if ((b != NULL) && (b[0] != NULL) && (b[0]->bv_val != NULL))
        return 1;
    return 0;
}

TPS_PUBLIC void set_tus_db_port(int number)
{
    port = number;
}

TPS_PUBLIC void set_tus_db_hostport(char *name)
{
    char *s = NULL;

    s = PL_strstr(name, ":");
    if (s == NULL) {
      set_tus_db_port(389);
    } else {
      set_tus_db_port(atoi(s+1));
      s[0] = '\0'; 
    } 
    set_tus_db_host(name);
}

TPS_PUBLIC void set_tus_db_host(char *name)
{
    if( ccHost > 0 && host != NULL ) {
        PL_strfree( host );
        host = NULL;
    }
    if( name != NULL ) {
        host = PL_strdup( name );
    }
    ccHost++;
}

TPS_PUBLIC void set_tus_db_baseDN(char *dn)
{
    if( ccBaseDN > 0 && baseDN != NULL ) {
        PL_strfree( baseDN );
        baseDN = NULL;
    }
    if( dn != NULL ) {
        baseDN = PL_strdup( dn );
    }
    ccBaseDN++;
}

TPS_PUBLIC void set_tus_db_userBaseDN(char *dn)
{
    if( userBaseDN != NULL ) {
        PL_strfree( userBaseDN );
        userBaseDN = NULL;
    }
    if( dn != NULL ) {
        userBaseDN = PL_strdup( dn );
    }
}

TPS_PUBLIC void set_tus_db_activityBaseDN(char *dn)
{
    if( activityBaseDN != NULL ) {
        PL_strfree( activityBaseDN );
        activityBaseDN = NULL;
    }
    if( dn != NULL ) {
        activityBaseDN = PL_strdup( dn );
    }
}

TPS_PUBLIC void set_tus_db_certBaseDN(char *dn)
{
    if( certBaseDN != NULL ) {
        PL_strfree( certBaseDN );
        certBaseDN = NULL;
    }
    if( dn != NULL ) {
        certBaseDN = PL_strdup( dn );
    }
}

TPS_PUBLIC void set_tus_db_bindDN(char *dn)
{
    if( ccBindDN > 0 && bindDN != NULL ) {
        PL_strfree( bindDN );
        bindDN = NULL;
    }
    if( dn != NULL ) {
        bindDN = PL_strdup( dn );
    }
    ccBindDN++;
}

TPS_PUBLIC void set_tus_db_bindPass(char *p)
{
    if( ccBindPass > 0 && bindPass != NULL ) {
        PL_strfree( bindPass );
        bindPass = NULL;
    }
    if( p != NULL ) {
        bindPass = PL_strdup( p );
    }
    ccBindPass++;
}

TPS_PUBLIC int is_tus_db_initialized()
{
    return ((ld != NULL && bindStatus == LDAP_SUCCESS)? 1: 0);
}

TPS_PUBLIC int get_tus_db_config(char *cfg_name)
{
    PRFileInfo info;
    PRFileDesc *fd = NULL;
    PRUint32   size;
    int  k, n, p;
    char *buf = NULL;
    char *s   = NULL;
    char *v   = NULL;

    if (PR_GetFileInfo (cfg_name, &info) != PR_SUCCESS)
        return 0;
    size = info.size;
    size++;
    buf = (char *)PR_Malloc(size);
    if (buf == NULL)
        return 0;

    fd = PR_Open(cfg_name, PR_RDONLY, 400);
    if (fd == NULL) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return 0;
    }

    k = 0;
    while ((n = PR_Read(fd, &buf[k], size-k-1)) > 0) {
        k += n;
        if ((PRUint32)(k+1) >= size) break;
    }
    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }
    if (n < 0 || ((PRUint32)(k+1) > size)) {
        if( buf != NULL ) {
            PR_Free( buf );
            buf = NULL;
        }
        return 0;
    }
    buf[k] = '\0';

    if ((s = PL_strstr(buf, "tokendb.hostport=")) != NULL) {

        s += 17;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_hostport(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.port=")) != NULL) {

        s += 13;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            p = atoi(s);
            set_tus_db_port(p);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.ssl=")) != NULL) {

        s += 12;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            if (strcmp(s, "") != 0) {
              ssl = PL_strdup( s );
            }
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.auditLog=")) != NULL) {

        s += 17;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            if (strcmp(s, "") != 0) {
              audit_fd = PR_Open(s, PR_RDWR | PR_CREATE_FILE | PR_APPEND,
                   400 | 200);
            }
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    if ((s = PL_strstr(buf, "tokendb.host=")) != NULL) {

        s += 13;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_host(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.defaultPolicy=")) != NULL) {

        s += 22;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            defaultPolicy = PL_strdup( s );
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.userBaseDN=")) != NULL) {
        s += 19;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_userBaseDN(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if ((s = PL_strstr(buf, "tokendb.baseDN=")) != NULL) {
        s += 15;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_baseDN(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    if ((s = PL_strstr(buf, "tokendb.activityBaseDN=")) != NULL) {
        s += strlen("tokendb.activityBaseDN=");
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_activityBaseDN(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    if ((s = PL_strstr(buf, "tokendb.certBaseDN=")) != NULL) {
        s += strlen("tokendb.certBaseDN=");
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_certBaseDN(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    if ((s = PL_strstr(buf, "tokendb.bindDN=")) != NULL) {
        s += 15;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            set_tus_db_bindDN(s);
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }
    if ((s = PL_strstr(buf, "tokendb.bindPassPath=")) != NULL) {
        s += 21;
        v = s;
        while (*s != '\x0D' && *s != '\x0A' && *s != '\0' && 
               (PRUint32)(s - buf) < size) {
            s++;
        }
        n = s - v;
        s = PL_strndup(v, n);
        if (s != NULL) {
            /* read tokendbBindPass from bindPassPath */
            char *p = NULL;
            p = get_pwd_from_conf(s, "tokendbBindPass");
            set_tus_db_bindPass(p);
            if (p) {
                if (debug_fd)
	              PR_fprintf(debug_fd, "freeing p - %s\n", p);
                PR_Free( p );
            }
            PL_strfree( s );
            s = NULL;
        } else {
            if( buf != NULL ) {
                PR_Free( buf );
                buf = NULL;
            }
            return 0;
        }
    }

    if( buf != NULL ) {
        PR_Free( buf );
        buf = NULL;
    }

    tus_db_end();

    return 1;
}


TPS_PUBLIC char *tus_authenticate(char *cert)
{
    char *dst;
    int len;
    int certlen;
    int  rc = -1;
#define MAX_FILTER_LEN 4096
    char filter[MAX_FILTER_LEN];
    char searchBase[MAX_FILTER_LEN];
    struct berval **v = NULL;
    char *userid = NULL;
    LDAPMessage *result = NULL;
    LDAPMessage *entry =  NULL;
    int i,j;
    char *certX = NULL;
    int tries;

    tus_check_conn();
    if (cert == NULL)
      return NULL;

    certlen = strlen(cert);

    certX = malloc(certlen);
    j = 0;
    for (i = 0; i < certlen; i++) {
       if (cert[i] != '\n' && cert[i] != '\r') {
         certX[j++] = cert[i];
       }
    } 
    certX[j++] = '\0';
    dst = malloc(3 * strlen(certX) / 4);
    len = base64_decode(certX, ( unsigned char * ) dst);
    free(certX);

    if (len <= 0) {
      if (dst != NULL) free(dst);
      return NULL;
    }

    PR_snprintf(filter, MAX_FILTER_LEN, "(userCertificate=");

    for (i = 0; i < len; i++) {
      char c = dst[i];
      PR_snprintf(filter, MAX_FILTER_LEN, "%s\\%02x", filter, (c & 0xff) );
    }
    PR_snprintf(filter, MAX_FILTER_LEN, "%s)", filter);
    PR_snprintf(searchBase, MAX_FILTER_LEN, "ou=People, %s", userBaseDN);

    if (dst != NULL) free(dst);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s(ld, searchBase, LDAP_SCOPE_SUBTREE, 
               filter, NULL, 0, NULL, NULL, NULL, 0, &result)) == LDAP_SUCCESS )  
		{
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
		}
	}
		
    if (rc != LDAP_SUCCESS) {
        if (result != NULL) {
            free_results(result);
            result = NULL;
        }
        return NULL;
    }

    if (result == NULL)
      return NULL;

    entry = get_first_entry (result);
    if (entry == NULL) {
        if (result != NULL) {
            free_results(result);
            result = NULL;
        }
        return NULL;
    }

    v = ldap_get_values_len(ld, entry, "uid");
    if (v == NULL) {
        if (result != NULL) {
            free_results(result);
            result = NULL;
        }
        return NULL;
    }

    if (valid_berval(v) && PL_strlen(v[0]->bv_val) > 0) {
        userid = PL_strdup(v[0]->bv_val);
    }
    if( v != NULL ) {
        ldap_value_free_len( v );
        v = NULL;
    }

    if (result != NULL) {
        free_results(result);
        result = NULL;
    }

    return userid;
}

/*********
 * tus_authorize
 * parameters passed in: 
 *   char * group ("TUS Agents", "TUS Operators", "TUS Administrators") 
 *   const char* userid
 * returns : 1 if userid is member of that group
 *           0 otherwise
 **/                    

TPS_PUBLIC int tus_authorize(const char *group, const char *userid)
{
    int rc;
    char filter[4096];
	int tries;
    LDAPMessage *result = NULL;

    PR_snprintf(filter, 4096, 
          "(&(cn=%s)(member=uid=%s,*))", group ,userid);
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s(ld, userBaseDN, LDAP_SCOPE_SUBTREE, 
               filter, NULL, 0, NULL, NULL, NULL, 0, &result))  == LDAP_SUCCESS )  
		{
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
		}
	}

    if (rc != LDAP_SUCCESS) {
      if (result != NULL) {
        free_results(result);
        result = NULL;
      }
      return 0;
    }
    if (ldap_count_entries (ld, result) <= 0) {
      if (result != NULL) {
        free_results(result);
        result = NULL;
      }
      return 0;
    }
    if (result != NULL) {
        free_results(result);
        result = NULL;
    }
    return 1;
}

/******
 * get_authorized_profiles()
 * params: userid 
 *       : is_admin (1 if user is in admin group, 0 otherwise
 * returns: ldap filter with the tokenTypes the user has access to - to be appended 
 *    to any other user search filer.
 *    examples: (|(tokenType=foo)(tokenType=bar)
 *    example: (!(tokenType=foo)(tokenType=no_token_type)) -- if user is an admin, always
 *        add no_token_type to catch admin events
 *    example: NO_PROFILES -- not an admin, and no profiles
 *    exmaple: (tokenType=no_token_type) : admin with no other tokens
 *
 *    Caller must free the result (char*)
 **/
TPS_PUBLIC char *get_authorized_profiles(const char *userid, int is_admin)
{
    int status;
    char filter[512];
    char ret[4096] = "";
    char *profile_filter = NULL;
    struct berval **vals = NULL;
    int nVals;
    int i;

    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;

//    Debug("TUS","get_authorized_profiles");
    PR_snprintf(filter, 512, "(uid=%s)", userid);
    status = find_tus_user_entries_no_vlv(filter, &result, 0);

    if (status == LDAP_SUCCESS) {

        e = get_first_entry(result);

        vals = get_attribute_values(e,"profileID");
        if (valid_berval(vals)) {
            nVals = ldap_count_values_len(vals);
            if (nVals == 1) {
                if (PL_strstr(vals[0]->bv_val, ALL_PROFILES)) {
                    if (is_admin) {
                        // all profiles
                        PR_snprintf(ret, 4096, ALL_PROFILES);
                    } else {
                        // all profile except admin no token events
                        PR_snprintf(ret, 4096, "(!(tokenType=%s))", NO_TOKEN_TYPE);
                    }
                } else {
                    if (is_admin) {
                        PL_strcat(ret, "(|(tokenType=");
                        PL_strcat(ret, NO_TOKEN_TYPE);
                        PL_strcat(ret, ")(tokenType=");
                        PL_strcat(ret, vals[0]->bv_val);
                        PL_strcat(ret, "))");
                    } else {
                        PL_strcat(ret, "(tokenType=");
                        PL_strcat(ret, vals[0]->bv_val);
                        PL_strcat(ret, ")");
                    }
                }
            } else if (nVals > 1) {
                for( i = 0; vals[i] != NULL; i++ ) {
                    if (i==0) { 
                        PL_strcat(ret, "(|");
                        if (is_admin) {
                            PL_strcat(ret, "(tokenType=");
                            PL_strcat(ret, NO_TOKEN_TYPE);
                            PL_strcat(ret, ")");
                        }
                    }
                    if (vals[i]->bv_val != NULL) {
                        PL_strcat(ret, "(tokenType=");
                        PL_strcat(ret, vals[i]->bv_val);
                        PL_strcat(ret, ")");
                    }
                }
                PL_strcat(ret, ")"); 
            } else if (nVals == 0) {
                if (is_admin) {
                    PR_snprintf(ret, 4096, "(tokenType=%s)", NO_TOKEN_TYPE);
                } else {
                    PR_snprintf(ret, 4096, NO_PROFILES);
                }
            } else { //error
                return NULL;
            }
        } else {
            if (is_admin) {
                PR_snprintf(ret, 4096, "(tokenType=%s)", NO_TOKEN_TYPE);
            } else {
                PR_snprintf(ret, 4096, NO_PROFILES);
            }
        }
    } else {
        // log error message here
        PR_snprintf(ret, 4096, NO_PROFILES);
    }

    profile_filter = PL_strdup(ret);

    if (vals != NULL) {
        free_values(vals, 1);
        vals =  NULL;
    }

    if (result != NULL) {
       free_results(result);
       result = NULL;
    }

    e = NULL;

    return profile_filter;
}

static int tus_check_conn()
{
    int  version = LDAP_VERSION3;
    int  status  = -1;
    char ldapuri[1024];

/* for production, make sure this variable is not defined.
 * Leaving it defined results in weird Apache SSL timeout errors */
/*#define DEBUG_TOKENDB*/

#ifdef DEBUG_TOKENDB
    debug_fd = PR_Open("/tmp/debugTUSdb.log",
           PR_RDWR | PR_CREATE_FILE | PR_APPEND,
                   400 | 200);
#endif
    if (ld == NULL) {
        if (ssl != NULL && strcmp(ssl, "true") == 0) {
          /* enabling SSL */
          snprintf(ldapuri, 1024, "ldaps://%s:%i", host, port);
        } else {
          snprintf(ldapuri, 1024, "ldap://%s:%i", host, port);
        }
        status = ldap_initialize(&ld, ldapuri);
        if (ld == NULL) {
            return status;
        }

        // This option was supported by mozldap but is not supported by openldap. 
        // Code to provide this functionality needs to be written - FIXME
        /*if ((status = ldap_set_option (ld, LDAP_OPT_RECONNECT, LDAP_OPT_ON)) != LDAP_SUCCESS) {
            return status;
        }*/

        if ((status = ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_SUCCESS) {
            return status;
        }
    }
    if (ld != NULL && bindStatus != LDAP_SUCCESS) {
        struct berval credential;
        credential.bv_val = bindPass;
        credential.bv_len= strlen(bindPass);
        bindStatus = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
        if (bindStatus != LDAP_SUCCESS) {
            return bindStatus;
        }
    }

    return LDAP_SUCCESS;
}

TPS_PUBLIC int tus_db_init(char **errorMsg)
{
    return LDAP_SUCCESS;
}

TPS_PUBLIC void tus_db_end()
{
    if (ld != NULL) {
        if (ldap_unbind_ext_s(ld, NULL, NULL) == LDAP_SUCCESS) {
            ld = NULL;
            bindStatus = -1;
        }
    }
}

TPS_PUBLIC void tus_db_cleanup()
{
    if (ssl != NULL) {
        PL_strfree(ssl);
        ssl = NULL;
    }
    if (host != NULL) { 
        PL_strfree(host);
        host = NULL;
    }
    if (userBaseDN != NULL) {
        PL_strfree(userBaseDN);
        userBaseDN = NULL;
    }
    if (baseDN != NULL) {
        PL_strfree(baseDN);
        baseDN = NULL;
    }
    if (activityBaseDN != NULL) {
        PL_strfree(activityBaseDN);
        activityBaseDN = NULL;
    }
    if(certBaseDN != NULL) { 
        PL_strfree(certBaseDN);
        certBaseDN = NULL;
    }
    if(bindDN != NULL) {
        PL_strfree(bindDN);
        bindDN = NULL;
    }
    if(bindPass != NULL) { 
        PL_strfree(bindPass);
        bindPass = NULL;
    }
    if(defaultPolicy != NULL) { 
        PL_strfree(defaultPolicy);
        defaultPolicy = NULL;
    }
    if (debug_fd != NULL) { 
        PR_Close(debug_fd);
        debug_fd = NULL;
    }
    if (audit_fd != NULL) {
        PR_Close(audit_fd);
        audit_fd = NULL;
    }
}

/*****
 * tus_print_integer
 * summary: prints serial number as hex string
 *          modeled on SECU_PrintInteger.  The length
 *          4 below is arbitrary - but works!
 *  params: out - output hexidecimal string
 *          data - serial number as SECItem 
 */
TPS_PUBLIC void tus_print_integer(char *out, SECItem *i)
{
    int iv;

    if (!i || !i->len || !i->data) {
        sprintf(out, "(null)");
    } else if (i->len > 4) {
        tus_print_as_hex(out, i);
    } else {
        if (i->type == siUnsignedInteger && *i->data & 0x80) {
            /* Make sure i->data has zero in the highest byte
             * if i->data is an unsigned integer */
            SECItem tmpI;
            char data[] = {0, 0, 0, 0, 0};

            PORT_Memcpy(data + 1, i->data, i->len);
            tmpI.len = i->len + 1;
            tmpI.data = (void*)data;

            iv = DER_GetInteger(&tmpI);
        } else {
            iv = DER_GetInteger(i);
        }
        sprintf(out, "%x", iv);
    }
}

/***
 * tus_print_as_hex
 * summary: prints serial number as a hex string, needed
 *          because DER_GetInteger only works for small numbers
 *          modeled on SECU_PrintAsHex
 * params:  out - output hexidecimal string
 *          data - serial number as SECItem
 */
TPS_PUBLIC void tus_print_as_hex(char *out, SECItem *data)
{
    unsigned i;
    int isString = 1;
    char tmp[32];

    PR_snprintf(out, 2, "");

    /* take a pass to see if it's all printable. */
    for (i = 0; i < data->len; i++) {
        unsigned char val = data->data[i];
        if (!val || !isprint(val)) {
            isString = 0;
            break;
        }
    }

    if (!isString) {
        for (i = 0; i < data->len; i++) {
            PR_snprintf(tmp, 32, "%02x", data->data[i]);
            PL_strcat(out, tmp);
        }
    } else {
        for (i = 0; i < data->len; i++) {
            unsigned char val = data->data[i];

            PR_snprintf(tmp, 32, "%c", val);
            PL_strcat(out, tmp);
        }
    }
    PL_strcat(out, '\0');
}

char **parse_number_change(int n)
{
    char tmp[32];
    int  l;
    char **v  = NULL;

    PR_snprintf(tmp, 32, "%d", n);
    l = PL_strlen(tmp);

    if ((v = allocate_values(1, l+1)) == NULL) {
        return NULL;
    }
    PL_strcpy(v[0], tmp);

    return v;
}

TPS_PUBLIC int update_cert_status (char *cn, const char *status)
{
    char dn[256];
    int  len;
    int  tries;
    int  rc = -1;
    char **v = NULL;
    LDAPMod **mods = NULL;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, certBaseDN) < 0)
        return -1;

        mods = allocate_modifications(2);
        if (mods == NULL)
            return -1;

        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }

        mods[0]->mod_op = LDAP_MOD_REPLACE;
        mods[0]->mod_type = tokenAttributes[I_TOKEN_M_DATE];
        mods[0]->mod_values = v;
        if (status != NULL && PL_strlen(status) > 0) {
            len = PL_strlen(status);
            if ((v = allocate_values(1, len+1)) == NULL) {
                if( mods != NULL ) {
                    free_modifications( mods, 0 );
                    mods = NULL;
                }
                return -1;
            }
            PL_strcpy(v[0], status);

            mods[1]->mod_op = LDAP_MOD_REPLACE;
            mods[1]->mod_type = "tokenStatus";
            mods[1]->mod_values = v;
        }

        for (tries = 0; tries < MAX_RETRIES; tries++) {
            if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
                break;
            } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
                struct berval credential;
                credential.bv_val = bindPass;
                credential.bv_len= strlen(bindPass);
                rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
                if (rc != LDAP_SUCCESS) {
                    bindStatus = rc;
                    break;
                }
            }
        }

        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }

    return rc;
}

TPS_PUBLIC int update_token_policy (char *cn, char *policy)
{
    char dn[256];
    int  len, k;
    int  tries;
    int  rc = -1;
    char **v = NULL;
    LDAPMod **mods = NULL;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

        mods = allocate_modifications(2);
        if (mods == NULL)
            return -1;

        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }

        mods[0]->mod_op = LDAP_MOD_REPLACE;
        mods[0]->mod_type = tokenAttributes[I_TOKEN_M_DATE];
        mods[0]->mod_values = v;
        k = 1;
        if (policy != NULL && PL_strlen(policy) > 0) {
            len = PL_strlen(policy);
            if ((v = allocate_values(1, len+1)) == NULL) {
                if( mods != NULL ) {
                    free_modifications( mods, 0 );
                    mods = NULL;
                }
                return -1;
            }
            PL_strcpy(v[0], policy);

            mods[k]->mod_op = LDAP_MOD_REPLACE;
            mods[k]->mod_type = tokenAttributes[I_TOKEN_POLICY];
            mods[k]->mod_values = v;
            k++;
        }

        for (tries = 0; tries < MAX_RETRIES; tries++) {
            if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
                break;
            } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
                struct berval credential;
                credential.bv_val = bindPass;
                credential.bv_len= strlen(bindPass);
                rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
                if (rc != LDAP_SUCCESS) {
                    bindStatus = rc;
                    break;
                }
            }
        }

        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }

    return rc;
}

TPS_PUBLIC int update_tus_db_entry_with_mods (const char *agentid, const char *cn, LDAPMod **mods)
{
    char dn[256];
    int  tries;
    int  rc = -1;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
            if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
                break;
            } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
                struct berval credential;
                credential.bv_val = bindPass;
                credential.bv_len= strlen(bindPass);
                rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
                if (rc != LDAP_SUCCESS) {
                    bindStatus = rc;
                    break;
                }
            }
    }

    if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
    }

    return rc;
}

/****
 * update_tus_general_db_entry
 * summary: internal function to modify a general db entry using ldap_modify_ext_s
 * params: agentid - who is doing this modification (for audit logging)
 *         dn - dn to modify
 *         mods - NULL terminated list of modifications to apply
 **/
int update_tus_general_db_entry(const char *agentid, const char *dn, LDAPMod **mods)
{
    int  tries;
    int  rc = -1;

    tus_check_conn();

    for (tries = 0; tries < MAX_RETRIES; tries++) {
            if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
                break;
            } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
                struct berval credential;
                credential.bv_val = bindPass;
                credential.bv_len= strlen(bindPass);
                rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
                if (rc != LDAP_SUCCESS) {
                    bindStatus = rc;
                    break;
                }
            }
    }

    return rc;
}

/***
 * update_user_db_entry
 * summary: modifies an existing user entry
 * params : agentid - agent that is performing this action (for audit log purposes)
 *          uid, lastName, firstName, userCN, userCert - for entry to be added
 * returns: ldap return code 
 * */         
TPS_PUBLIC int update_user_db_entry(const char *agentid, char *uid, char *lastName, char *firstName, char *userCN, char *userCert)
{
    char dn[256];
    LDAPMod a01;
    LDAPMod a02;
    LDAPMod a03;
    LDAPMod a04;
    LDAPMod *mods[5];
    int rc = -1;
    int certlen=0;
    int i,j;
    char *certX = NULL;
    char *dst = NULL;

    char *sn_values[] = {lastName, NULL};
    char *givenName_values[] = {firstName, NULL};
    char *cn_values[] = {userCN, NULL};
    struct berval berval;
    struct berval *cert_values[2];

    a01.mod_op = LDAP_MOD_REPLACE;
    a01.mod_type = USER_SN;
    a01.mod_values = sn_values;

    a02.mod_op = LDAP_MOD_REPLACE;
    a02.mod_type = USER_CN;
    a02.mod_values = cn_values;

    a03.mod_op = LDAP_MOD_REPLACE;
    a03.mod_type = USER_GIVENNAME;
    a03.mod_values = ((firstName != NULL && PL_strlen(firstName) > 0)? givenName_values: NULL);

    mods[0] = &a01;
    mods[1] = &a02;
    mods[2] = &a03;

    certlen = strlen(userCert);

    certX = malloc(certlen);
    j = 0;
    for (i = 0; i < certlen; i++) {
       if (userCert[i] != '\n' && userCert[i] != '\r') {
         certX[j++] = userCert[i];
       }
    }
    certX[j++] = '\0';
    dst = malloc(3 * strlen(certX) / 4);
    certlen = base64_decode(certX, ( unsigned char * ) dst);
    free(certX);

    if (certlen > 0) {
        berval.bv_len = certlen;
        berval.bv_val = ( char * ) dst;
        cert_values[0] = &berval;
        cert_values[1] = NULL;

        a04.mod_op =LDAP_MOD_REPLACE |LDAP_MOD_BVALUES;
        a04.mod_type = "userCertificate";
        a04.mod_bvalues = cert_values;

        mods[3] = &a04;
    } else {
        mods[3] = NULL;
    }

    mods[4] = NULL;

    if (PR_snprintf(dn, 255, "uid=%s, ou=People, %s", uid, userBaseDN) < 0 ) 
       return -1;

    rc = update_tus_general_db_entry(agentid, dn, mods);
    if (dst != NULL) free(dst);
    if (rc == LDAP_SUCCESS) 
      audit_log("modify_user", agentid, uid);

    return rc;
}

TPS_PUBLIC int update_tus_db_entry (const char *agentid, char *cn, const char *uid, char *keyInfo, const char *status, char *applet_version, const char *reason, const char* token_type)
{
    char dn[256];
    int  len, k;
    int  tries;
    int  rc = -1;
    char **v = NULL;
    LDAPMod **mods = NULL;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

        if (keyInfo == NULL && token_type == NULL)
            mods = allocate_modifications(5);
        else if (keyInfo == NULL || token_type == NULL)
            mods = allocate_modifications(6);
        else
            mods = allocate_modifications(7);
        if (mods == NULL)
            return -1;

        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }

        mods[0]->mod_op = LDAP_MOD_REPLACE;
        mods[0]->mod_type = tokenAttributes[I_TOKEN_M_DATE];
        mods[0]->mod_values = v;
        k = 1;
        if (applet_version != NULL && PL_strlen(applet_version) > 0) {
            len = PL_strlen(applet_version);
            if ((v = allocate_values(1, len+1)) == NULL) {
                if( mods != NULL ) {
                    free_modifications( mods, 0 );
                    mods = NULL;
                }
                return -1;
            }
            PL_strcpy(v[0], applet_version);

            mods[k]->mod_op = LDAP_MOD_REPLACE;
            mods[k]->mod_type = tokenAttributes[I_TOKEN_APPLET];
            mods[k]->mod_values = v;
            k++;
        }

    /* for userid */
    if (uid != NULL && PL_strlen(uid) > 0)
        len = PL_strlen(uid);
    else
        len = 0;
    if ((v = allocate_values(1, len+1)) == NULL) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return -1;
    }
    mods[k]->mod_op = LDAP_MOD_REPLACE;
    mods[k]->mod_type = "tokenUserID";
    if (uid != NULL && PL_strlen(uid) > 0)
        PL_strcpy(v[0], uid);
    else
        v[0] = "";
    mods[k]->mod_values = v;
    k++;

        if (status != NULL && PL_strlen(status) > 0) {
            len = PL_strlen(status);
            if ((v = allocate_values(1, len+1)) == NULL) {
                if( mods != NULL ) {
                    free_modifications( mods, 0 );
                    mods = NULL;
                }
                return -1;
            }
            PL_strcpy(v[0], status);

            mods[k]->mod_op = LDAP_MOD_REPLACE;
            mods[k]->mod_type = tokenAttributes[I_TOKEN_STATUS];
            mods[k]->mod_values = v;
            k++;
        }

    /* for tokenReason */
    if (reason != NULL && PL_strlen(reason) > 0)
        len = PL_strlen(reason);
    else
        len = 0;
    if ((v = allocate_values(1, len+1)) == NULL) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return -1;
    }
    mods[k]->mod_op = LDAP_MOD_REPLACE;
    mods[k]->mod_type = "tokenReason";
    if (reason != NULL && PL_strlen(reason) > 0)
        PL_strcpy(v[0], reason);
    else
        v[0] = "";
    mods[k]->mod_values = v;
    k++;

    /* for keyinfo */
    if (keyInfo != NULL) {
        if (keyInfo != NULL && PL_strlen(keyInfo) > 0)
            len = PL_strlen(keyInfo);
        else
            len = 0;
        if ((v = allocate_values(1, len+1)) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = tokenAttributes[I_TOKEN_KEY_INFO];
        if (keyInfo != NULL && PL_strlen(keyInfo) > 0)
            PL_strcpy(v[0], keyInfo);
        else
            v[0] = "";
        mods[k]->mod_values = v;
        k++;
    }

    /* for token_type */
    if (token_type != NULL) {
        if (token_type != NULL && PL_strlen(token_type) > 0)
            len = PL_strlen(token_type);
        else
            len = 0;
        if ((v = allocate_values(1, len+1)) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
        mods[k]->mod_op = LDAP_MOD_REPLACE;
        mods[k]->mod_type = TOKEN_TYPE;
        if (len > 0)
            PL_strcpy(v[0], token_type);
        else
            v[0] = "";
        mods[k]->mod_values = v;
        k++;
    }

        for (tries = 0; tries < MAX_RETRIES; tries++) {
            if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
                break;
            } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
                struct berval credential;
                credential.bv_val = bindPass;
                credential.bv_len= strlen(bindPass);
                rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
                if (rc != LDAP_SUCCESS) {
                    bindStatus = rc;
                    break;
                }
            }
        }

        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }

    return rc;
}

int check_and_modify_tus_db_entry (char *userid, char *cn, char *check, LDAPMod **mods)
{
    char dn[256];
    int  rc = 0, tries = 0;

    if (check == NULL) { 
        return -1;
    }

    struct berval check_ber;
    check_ber.bv_val = check;
    check_ber.bv_len = strlen(check);

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_compare_ext_s(ld, dn, get_number_of_modifications_name(), &check_ber, NULL, NULL))
            == LDAP_COMPARE_TRUE) {
            break;
        } else {
            if (rc != LDAP_SERVER_DOWN && rc != LDAP_CONNECT_ERROR) {
                return rc;
            }
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                return rc;
            }
        }
    }
    if (tries >= MAX_RETRIES)
        return rc;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    /* audit log */
    if (rc == LDAP_SUCCESS) {
      audit_log("check_and_modify_token", userid, cn);
    }

    return rc;
}

int modify_tus_db_entry (char *userid, char *cn, LDAPMod **mods)
{
    char dn[256];
    int  rc = 0, tries = 0;

    tus_check_conn();
    if (ld == NULL) {
      if (debug_fd)
	PR_fprintf(debug_fd, "tus_db mod: ld null...no ldap");
      return -1;
    }
    if (mods == NULL) {
      if (debug_fd)
	PR_fprintf(debug_fd, "tus_db mod: mods null, can't modify");
      return -1;
    }
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;
    if (debug_fd)
      PR_fprintf(debug_fd, "tus_db mod: modifying :%s\n",dn);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
    if (debug_fd)
      PR_fprintf(debug_fd, "tus_db mod: tries=%d\n",tries);
        if ((rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    if (rc == LDAP_SUCCESS) {
      audit_log("modify_token", userid, cn);
    }

    return rc;
}

int add_certificate (char *tokenid, char *origin, char *tokenType, char *userid, CERTCertificate *certificate, char *ktype, const char *status)
{
    PRExplodedTime time;
    PRTime   now;
    LDAPMod  a01;
    LDAPMod  a02;
    LDAPMod  a03;
    LDAPMod  a04;
    LDAPMod  a05;
    LDAPMod  a06;
    LDAPMod  a07;
    LDAPMod  a08;
    LDAPMod  a09;
    LDAPMod  a10;
    LDAPMod  a11;
    LDAPMod  a12;
    LDAPMod  a13;
    LDAPMod  a14;
    LDAPMod  a15;
    LDAPMod  a16;
    LDAPMod  *mods[17];
    int  rc = 0, tries = 0;
    char dn[2049];
    char cdate[256];
    char name[2048];
    char x_not_before[2048];
    char x_not_after[2048];
    char serialnumber[2048];
    char *serial_values[2];
    char *cn_values[2];
    char *issuer_values[2];
    char *subject_values[2];
    char *cdate_values[2];
    char *id_values[2];
    char *userid_values[2];
    char *type_values[2];
    char *key_type_values[2];
    char *origin_values[2];
    char *status_values[2];
    char *not_before_values[2];
    char *not_after_values[2];
    PRThread *ct;
    struct berval berval;
    struct berval *cert_values[2]; 
    char *objectClass_values[] = { "top", "tokenCert", NULL };
    PRTime not_before,not_after;
    char zcdate[256];

    tus_check_conn();
    ct = PR_GetCurrentThread();
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_snprintf(cdate, 16, "%04d%02d%02d%02d%02d%02dZ",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    /* unique id per activity */
    tus_print_integer(serialnumber, &certificate->serialNumber);

    PR_snprintf(name, 16, "%04d%02d%02d%02d%02d%02dZ",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    /* unique id per activity */
    PR_snprintf(zcdate, 256, "%s.%04d%02d%02d%02d%02d%02d",
                serialnumber, 
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    cn_values[0] = zcdate;
    cn_values[1] = NULL;

    a01.mod_op = 0;
    a01.mod_type = TOKEN_ID;
    a01.mod_values = cn_values;

    a02.mod_op = 0;
    a02.mod_type = "objectClass";
    a02.mod_values = objectClass_values;

    cdate_values[0] = cdate;
    cdate_values[1] = NULL;
    a03.mod_op = 0;
    a03.mod_type = TOKEN_C_DATE;
    a03.mod_values = cdate_values;

    a04.mod_op = 0;
    a04.mod_type = TOKEN_M_DATE;
    a04.mod_values = cdate_values;

    id_values[0] = tokenid;
    id_values[1] = NULL;
    a05.mod_op = 0;
    a05.mod_type = TOKEN_CUID;
    a05.mod_values = id_values;
    
    userid_values[0] = userid;
    userid_values[1] = NULL;
    a06.mod_op = 0;
    a06.mod_type = TOKEN_USER;
    a06.mod_values = userid_values;

    berval.bv_len = certificate->derCert.len;
    berval.bv_val = ( char * ) certificate->derCert.data;
    cert_values[0] = &berval;
    cert_values[1] = NULL;

    a07.mod_op = LDAP_MOD_BVALUES;
    a07.mod_type = TOKEN_CERT;
    a07.mod_values = ( char ** ) cert_values;

    subject_values[0] = certificate->subjectName;
    subject_values[1] = NULL;
    a08.mod_op = 0;
    a08.mod_type = TOKEN_SUBJECT;
    a08.mod_values = subject_values;

    issuer_values[0] = certificate->issuerName;
    issuer_values[1] = NULL;
    a09.mod_op = 0;
    a09.mod_type = TOKEN_ISSUER;
    a09.mod_values = issuer_values;

    serial_values[0] = serialnumber;
    serial_values[1] = NULL;
    a10.mod_op = 0;
    a10.mod_type = TOKEN_SERIAL;
    a10.mod_values = serial_values;

    type_values[0] = tokenType;
    type_values[1] = NULL;
    a11.mod_op = 0;
    a11.mod_type = TOKEN_TYPE;
    a11.mod_values = type_values;

    key_type_values[0] = ktype;
    key_type_values[1] = NULL;
    a12.mod_op = 0;
    a12.mod_type = TOKEN_KEY_TYPE;
    a12.mod_values = key_type_values;

    status_values[0] = ( char * ) status;
    status_values[1] = NULL;
    a13.mod_op = 0;
    a13.mod_type = TOKEN_STATUS;
    a13.mod_values = status_values;

    CERT_GetCertTimes (certificate, &not_before, &not_after);

    PR_ExplodeTime(not_before, PR_LocalTimeParameters, &time);
    PR_snprintf(x_not_before, 16, "%04d%02d%02d%02d%02d%02dZ",
            time.tm_year, (time.tm_month + 1), time.tm_mday,
            time.tm_hour, time.tm_min, time.tm_sec);

    not_before_values[0] = x_not_before;
    not_before_values[1] = NULL;
    a14.mod_op = 0;
    a14.mod_type = TOKEN_NOT_BEFORE;
    a14.mod_values = not_before_values;

    PR_ExplodeTime(not_after, PR_LocalTimeParameters, &time);
    PR_snprintf(x_not_after, 16, "%04d%02d%02d%02d%02d%02dZ",
            time.tm_year, (time.tm_month + 1), time.tm_mday,
            time.tm_hour, time.tm_min, time.tm_sec);

    not_after_values[0] = x_not_after;
    not_after_values[1] = NULL;
    a15.mod_op = 0;
    a15.mod_type = TOKEN_NOT_AFTER;
    a15.mod_values = not_after_values;

    origin_values[0] = origin;
    origin_values[1] = NULL;
    a16.mod_op = 0;
    a16.mod_type = TOKEN_ORIGIN;
    a16.mod_values = origin_values;

    mods[0]  = &a01;
    mods[1]  = &a02;
    mods[2]  = &a03;
    mods[3]  = &a04;
    mods[4]  = &a05;
    mods[5]  = &a06;
    mods[6]  = &a07;
    mods[7]  = &a08;
    mods[8]  = &a09;
    mods[9]  = &a10;
    mods[10]  = &a11;
    mods[11]  = &a12;
    mods[12]  = &a13;
    mods[13]  = &a14;
    mods[14]  = &a15;
    mods[15]  = &a16;
    mods[16]  = NULL;

    if (PR_snprintf(dn, 2048, "cn=%s,%s", cn_values[0], certBaseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}
int add_activity (const char *ip, const char *id, const char *op, const char *result, const char *msg, const char *userid, const char *token_type)
{
    PRExplodedTime time;
    PRTime   now;
    LDAPMod  a01;
    LDAPMod  a02;
    LDAPMod  a03;
    LDAPMod  a04;
    LDAPMod  a05;
    LDAPMod  a06;
    LDAPMod  a07;
    LDAPMod  a08;
    LDAPMod  a09;
    LDAPMod  a10;
    LDAPMod  a11;
    LDAPMod  *mods[12];
    int  rc = 0, tries = 0;
    char dn[256];
    char cdate[256];
    char zcdate[256];
    char *cn_values[2];
    char *objectClass_values[] = { "top", "tokenActivity", NULL };
    char *cdate_values[2];
    char *id_values[2];
    char *result_values[2];
    char *op_values[2];
    char *msg_values[2];
    char *ip_values[2];
    char *userid_values[2];
    char *token_type_values[2];
    PRThread *ct;

    tus_check_conn();
    id_values[0] =  (char *) id;
    id_values[1] = NULL;
    result_values[0] = ( char * ) result;
    result_values[1] = NULL;
    op_values[0] = ( char * ) op;
    op_values[1] = NULL;
    msg_values[0] = ( char * ) msg;
    msg_values[1] = NULL;
    ip_values[0] = (char *) ip;
    ip_values[1] = NULL;
    userid_values[0] = (char *) userid;
    userid_values[1] = NULL;
    token_type_values[0] = (char *) token_type;
    token_type_values[1] = NULL;

    ct = PR_GetCurrentThread();
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_snprintf(cdate, 16, "%04d%02d%02d%02d%02d%02dZ",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    /* unique id per activity */
    PR_snprintf(zcdate, 256, "%04d%02d%02d%02d%02d%02d%06d.%x",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec, time.tm_usec, ct);

    cn_values[0] = zcdate;
    cn_values[1] = NULL;

    a01.mod_op = 0;
    a01.mod_type = TOKEN_ID;
    a01.mod_values = cn_values;

    a02.mod_op = 0;
    a02.mod_type = "objectClass";
    a02.mod_values = objectClass_values;

    cdate_values[0] = cdate;
    cdate_values[1] = NULL;
    a03.mod_op = 0;
    a03.mod_type = TOKEN_C_DATE;
    a03.mod_values = cdate_values;

    a04.mod_op = 0;
    a04.mod_type = TOKEN_M_DATE;
    a04.mod_values = cdate_values;

    a05.mod_op = 0;
    a05.mod_type = TOKEN_CUID;
    a05.mod_values = id_values;
    
    a06.mod_op = 0;
    a06.mod_type = TOKEN_OP;
    a06.mod_values = op_values;

    a07.mod_op = 0;
    a07.mod_type = TOKEN_MSG;
    a07.mod_values = msg_values;

    a08.mod_op = 0;
    a08.mod_type = TOKEN_RESULT;
    a08.mod_values = result_values;

    a09.mod_op = 0;
    a09.mod_type = TOKEN_IP;
    a09.mod_values = ip_values;

    a10.mod_op = 0;
    a10.mod_type = TOKEN_USER;
    a10.mod_values = userid_values;

    a11.mod_op = 0;
    a11.mod_type = TOKEN_TYPE;
    a11.mod_values = token_type_values;
    mods[0]  = &a01;
    mods[1]  = &a02;
    mods[2]  = &a03;
    mods[3]  = &a04;
    mods[4]  = &a05;
    mods[5]  = &a06;
    mods[6]  = &a07;
    mods[7]  = &a08;
    mods[8]  = &a09;
    mods[9]  = &a10;
    mods[10]  = &a11;
    mods[11]  = NULL;

    if (PR_snprintf(dn, 255, "cn=%s,%s", zcdate, activityBaseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

/**
 * add_tus_general_db_entry
 * summary: internal function to add a general ldap entry 
 * params: dn = dn to add
 *         mods = NULL terminated list of modifications (contains attribute values)
 * returns: LDAP return code
 **/
int add_tus_general_db_entry (char *dn, LDAPMod **mods)
{
    int  rc = 0, tries = 0;

    tus_check_conn();

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }

    }
    return rc;
}

int add_tus_db_entry (char *cn, LDAPMod **mods)
{
    char dn[256];
    int  rc = 0, tries = 0;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

int add_new_tus_db_entry (const char *userid, char *cn, const char *uid, int flag, const char *status, char *applet_version, char *key_info, const char* token_type)
{
    PRExplodedTime time;
    PRTime   now;
    LDAPMod  a01;
    LDAPMod  a02;
    LDAPMod  a03;
    LDAPMod  a04;
    LDAPMod  a05;
    LDAPMod  a06;
    LDAPMod  a07;
    LDAPMod  a08;
    LDAPMod  a09;
    LDAPMod  a10;
    LDAPMod  a11;
    LDAPMod  a12;
    LDAPMod  a13;
    LDAPMod  a14;
    LDAPMod  a15;
    LDAPMod  a16;
    LDAPMod  *mods[17];
    int  rc = 0, tries = 0;
    char dn[256];
    char cdate[256];
    char *cn_values[2];
    char *objectClass_values[] = { "top", "tokenRecord", NULL };
    char *cdate_values[2];
    char *modified_values[] = { "0", NULL };
    char *uid_values[] = { "", NULL };
    char *status_values[] = { "", NULL };
    char *aid_values[] = { "", NULL };
    char *resets_values[] = { "0", NULL };
    char *enrollments_values[] = { "0", NULL };
    char *renewals_values[] = { "0", NULL };
    char *recoveries_values[] = { "0", NULL };
    char *key_info_values[] = { "", NULL };
    char *reason_values[] = { "", NULL };
    char *policy_values[2];
    char *token_type_values[]= {"", NULL };

    tus_check_conn();
    cn_values[0] = cn;
    cn_values[1] = NULL;

    policy_values[0] = defaultPolicy;
    policy_values[1] = NULL;

    if (uid != NULL) uid_values[0] = ( char * ) uid;
    if (key_info != NULL) key_info_values[0] = key_info;
    status_values[0] = ( char * ) status;
    token_type_values[0] = ( char *) token_type;

    a01.mod_op = 0;
    a01.mod_type = TOKEN_ID;
    a01.mod_values = cn_values;

    a02.mod_op = 0;
    a02.mod_type = "objectClass";
    a02.mod_values = objectClass_values;

    cdate_values[0] = cdate;
    cdate_values[1] = NULL;
    a03.mod_op = 0;
    a03.mod_type = TOKEN_C_DATE;
    a03.mod_values = cdate_values;

    a04.mod_op = 0;
    a04.mod_type = TOKEN_M_DATE;
    a04.mod_values = cdate_values;

    a05.mod_op = 0;
    a05.mod_type = TOKEN_MODS;
    a05.mod_values = modified_values;
    
    a06.mod_op = 0;
    a06.mod_type = TOKEN_USER;
    a06.mod_values = uid_values;

    a07.mod_op = 0;
    a07.mod_type = TOKEN_STATUS;
    a07.mod_values = status_values;

    a08.mod_op = 0;
    a08.mod_type = TOKEN_APPLET;
    if (applet_version != NULL) {
        aid_values[0] = applet_version;
    }
    a08.mod_values = aid_values;

    a09.mod_op = 0;
    a09.mod_type = TOKEN_RESETS;
    a09.mod_values = resets_values;

    a10.mod_op = 0;
    a10.mod_type = TOKEN_ENROLLMENTS;
    a10.mod_values = enrollments_values;

    a11.mod_op = 0;
    a11.mod_type = TOKEN_RENEWALS;
    a11.mod_values = renewals_values;

    a12.mod_op = 0;
    a12.mod_type = TOKEN_RECOVERIES;
    a12.mod_values = recoveries_values;

    a13.mod_op = 0;
    a13.mod_type = TOKEN_KEY_INFO;
    a13.mod_values = key_info_values;

    a14.mod_op = 0;
    a14.mod_type = TOKEN_POLICY;
    a14.mod_values = policy_values;

    a15.mod_op = 0;
    a15.mod_type = TOKEN_REASON;
    a15.mod_values = reason_values;

    a16.mod_op = 0;
    a16.mod_type = TOKEN_TYPE;
    a16.mod_values = token_type_values;

    mods[0]  = &a01;
    mods[1]  = &a02;
    mods[2]  = &a03;
    mods[3]  = &a04;
    mods[4]  = &a05;
    mods[5]  = &a06;
    mods[6]  = &a07;
    mods[7]  = &a08;
    mods[8]  = &a09;
    mods[9]  = &a10;
    mods[10] = &a11;
    mods[11] = &a12;
    mods[12] = &a13;
    mods[13] = &a14;
    mods[14] = &a15;
    mods[15] = &a16;
    mods[16] = NULL;

    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);

    PR_snprintf(cdate, 16, "%04d%02d%02d%02d%02d%02dZ",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_add_ext_s(ld, dn, mods, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    /* audit log */
    if (rc == LDAP_SUCCESS) {
      audit_log("add_token", userid, cn);
    }

    return rc;
}

TPS_PUBLIC int add_default_tus_db_entry (const char *uid, const char *agentid, char *cn, const char *status, char *applet_version, char *key_info, const char *token_type)
{
    return add_new_tus_db_entry (agentid, cn, uid, 0, status, applet_version, key_info, token_type);
}

/****
 * add_user_db_entry
 * summary: adds a new user entry
 * params: agentid - user who is performing this change (for audit log)
 *       :userid, userPassword, sn, givenName, cn, userCert - details for user to be added
 * returns: ldap return code
 */
TPS_PUBLIC int add_user_db_entry(const char *agentid, char *userid, char *userPassword, char *sn, char *givenName, char *cn, char *userCert)
{
    LDAPMod  a01;
    LDAPMod  a02;
    LDAPMod  a03;
    LDAPMod  a04;
    LDAPMod  a05;
    LDAPMod  a06;
    LDAPMod  a07;
    LDAPMod  *mods[8];
    int  rc = 0;
    char dn[256];
    int i,j, certlen;
    char *dst = NULL;
    char *certX = NULL;
    char *userid_values[] = {userid, NULL};
    char *objectClass_values[] = { "top", "person", "organizationalPerson", "inetOrgPerson", "tpsProfileId", NULL };
    char *userPassword_values[] = { userPassword, NULL };
    char *sn_values[] = {sn, NULL};
    char *cn_values[] = {cn, NULL};
    char *givenName_values[] = {givenName, NULL};
    struct berval berval;
    struct berval *userCert_values[2];

    a01.mod_op = 0;
    a01.mod_type = USER_ID;
    a01.mod_values = userid_values;

    a02.mod_op = 0;
    a02.mod_type = "objectClass";
    a02.mod_values = objectClass_values;

    a03.mod_op =0;
    a03.mod_type = USER_PASSWORD;
    a03.mod_values = userPassword_values;

    a04.mod_op = 0;
    a04.mod_type = USER_SN;
    a04.mod_values = sn_values;

    a05.mod_op =0;
    a05.mod_type = USER_CN;
    a05.mod_values = cn_values;

    a06.mod_op =0;
    a06.mod_type = USER_GIVENNAME;
    a06.mod_values = givenName_values;

    mods[0]  = &a01;
    mods[1]  = &a02;
    mods[2]  = &a03;
    mods[3]  = &a04;
    mods[4]  = &a05;
    if (givenName != NULL && PL_strlen(givenName) > 0) {
        mods[5]  = &a06;
    }

    // now handle certificate
    certlen = strlen(userCert);

    certX = malloc(certlen);
    j = 0;
    for (i = 0; i < certlen; i++) {
       if (userCert[i] != '\n' && userCert[i] != '\r') {
         certX[j++] = userCert[i];
       }
    }
    certX[j++] = '\0';
    dst = malloc(3 * strlen(certX) / 4);
    certlen = base64_decode(certX, ( unsigned char * ) dst);
    free(certX);

    if (certlen > 0) {
        berval.bv_len = certlen;
        berval.bv_val = ( char * ) dst;
        userCert_values[0] = &berval;
        userCert_values[1] = NULL;

        a07.mod_op = LDAP_MOD_BVALUES;
        a07.mod_type = USER_CERT;
        a07.mod_bvalues = userCert_values;
        
        if (givenName != NULL && PL_strlen(givenName) > 0) {
            mods[6] = &a07;
        } else {
            mods[5] = &a07;
        }
    } else {
        if (givenName == NULL || PL_strlen(givenName) == 0) {
            mods[5] = NULL;
        }
        mods[6] = NULL;
    }

    mods[7] = NULL;

    if (PR_snprintf(dn, 255, "uid=%s,ou=People, %s", userid, userBaseDN) < 0)
        return -1;

    rc = add_tus_general_db_entry(dn, mods);
    if (dst != NULL) free(dst);

    if (rc != LDAP_SUCCESS) {
        return rc;
    }

    audit_log("add_user", agentid, userid);
    return rc;
}

/**
 * add_user_to_role_db_entry
 * summary: adds user to be member of group (administrators, agents, operators)
 * params: agentid -user who is performing this change
 *       : userid - userid of user to be added to role
 *       : role - Operators, Agents or Administrators
 * returns: LDAP return code
 */
TPS_PUBLIC int add_user_to_role_db_entry(const char *agentid, char *userid, const char *role) {
    LDAPMod  a01;
    LDAPMod  *mods[2];
    int  rc = 0;
    char dn[256];
    char userdn[256];
    char msg[256];
    char *userid_values[2]; 

    if (PR_snprintf(userdn, 255, "uid=%s, ou=People, %s", userid, userBaseDN) < 0)
         return -1;

    userid_values[0] = userdn;
    userid_values[1] = NULL;

    a01.mod_op = LDAP_MOD_ADD;
    a01.mod_type = GROUP_MEMBER;
    a01.mod_values = userid_values;
    mods[0]  = &a01;
    mods[1]  = NULL;

    if (PR_snprintf(dn, 255, "cn=TUS %s,ou=groups, %s", role, userBaseDN) < 0)
            return -1;

    rc = update_tus_general_db_entry(agentid, dn, mods);

    if (rc == LDAP_SUCCESS) {
        PR_snprintf(msg, 256, "Added role %s to user %s", role, userid); 
        audit_log("add_user_to_role", agentid, msg);
    }
    return rc;
}

/**
 * delete_user_to_role_db_entry
 * summary: removes user from role group (administrators, agents, operators)
 * params: agentid -user who is performing this change
 *       : userid - userid of user to be removed from role
 *       : role - Operators, Agents or Administrators
 *  returns: LDAP return code
 */
TPS_PUBLIC int delete_user_from_role_db_entry(const char *agentid, char *userid, const char *role) {
    LDAPMod  a01;
    LDAPMod  *mods[2];
    int  rc = 0;
    char dn[256];
    char userdn[256];
    char *userid_values[2];
    char msg[256];

    if (PR_snprintf(userdn, 255, "uid=%s, ou=People, %s", userid, userBaseDN) < 0)
         return -1;

    userid_values[0] = userdn;
    userid_values[1] = NULL;

    a01.mod_op = LDAP_MOD_DELETE;
    a01.mod_type = GROUP_MEMBER;
    a01.mod_values = userid_values;
    mods[0]  = &a01;
    mods[1]  = NULL;

    if (PR_snprintf(dn, 255, "cn=TUS %s,ou=groups, %s", role, userBaseDN) < 0)
            return -1;

    rc = update_tus_general_db_entry(agentid, dn, mods);
    if (rc == LDAP_SUCCESS) {
        PR_snprintf(msg, 256, "Deleted role %s from user %s", role, userid); 
        audit_log("delete_user_from_role", agentid, msg);
    }

    return rc;
}

/**
 * delete_profile_from_user
 * summary: removes attribute profileID=profile from user entry
 * params: agentid -user who is performing this change
 *       : userid - userid of user to be modified
 *       : profile - profile to be deleted
 * returns: LDAP return code
 */
TPS_PUBLIC int delete_profile_from_user(const char *agentid, char *userid, const char *profile) {
    LDAPMod  a01;
    LDAPMod  *mods[2];
    int  rc = 0;
    char dn[256];
    char msg[256];
    char *profileid_values[2] = {(char *) profile, NULL};

    if (PR_snprintf(dn, 255, "uid=%s, ou=People, %s", userid, userBaseDN) < 0)
         return -1;

    a01.mod_op = LDAP_MOD_DELETE;
    a01.mod_type = PROFILE_ID;
    a01.mod_values = profileid_values;
    mods[0]  = &a01;
    mods[1]  = NULL;

    rc = update_tus_general_db_entry(agentid, dn, mods);
    if (rc == LDAP_SUCCESS) {
        PR_snprintf(msg, 256, "Deleted profile %s from user %s", profile, userid); 
        audit_log("delete_profile_from_user", agentid, msg);
    }

    return rc;
}

/**
 * delete_all_profiles_from_user
 * summary: removes all attributes profileID from user entry 
 *          same as above, but passing NULL for mod_values
 * params: agentid -user who is performing this change
 *       : userid - userid of user to be modified
 *       : profile - profile to be deleted
 * returns: LDAP return code
 */
TPS_PUBLIC int delete_all_profiles_from_user(const char *agentid, char *userid) {
    LDAPMod  a01;
    LDAPMod  *mods[2];
    int  rc = 0;
    char dn[256];
    char msg[256];

    if (PR_snprintf(dn, 255, "uid=%s, ou=People, %s", userid, userBaseDN) < 0)
         return -1;

    a01.mod_op = LDAP_MOD_DELETE;
    a01.mod_type = PROFILE_ID;
    a01.mod_values = NULL;  /* NULL will remove all values */
    mods[0]  = &a01;
    mods[1]  = NULL;

    rc = update_tus_general_db_entry(agentid, dn, mods);
    if (rc == LDAP_SUCCESS) {
        PR_snprintf(msg, 256, "Deleted all profiles from user %s", userid); 
        audit_log("delete_all_profiles_from_user", agentid, msg);
    }

    return rc;
}


/**
 * add_profile_to_user
 * summary: adds attribute profileID=profile to user entry
 * params: agentid -user who is performing this change
 *       : userid - userid of user to be modified
 *       : profile - profile (tokenType) to be added
 * returns: LDAP return code
 */
TPS_PUBLIC int add_profile_to_user(const char *agentid, char *userid, const char *profile) {
    LDAPMod  a01;
    LDAPMod  *mods[2];
    int  rc = 0;
    char dn[256];
    char msg[256];
    char *profileid_values[2] = {(char *) profile, NULL};

    if (PR_snprintf(dn, 255, "uid=%s, ou=People, %s", userid, userBaseDN) < 0)
         return -1;

    a01.mod_op = LDAP_MOD_ADD;
    a01.mod_type = PROFILE_ID;
    a01.mod_values = profileid_values;
    mods[0]  = &a01;
    mods[1]  = NULL;

    rc = update_tus_general_db_entry(agentid, dn, mods);
    if (rc == LDAP_SUCCESS) {
        PR_snprintf(msg, 256, "Added profile %s to user %s", profile, userid); 
        audit_log("add_profile_to_user", agentid, msg);
    }

    return rc;
}

int delete_tus_db_entry (char *userid, char *cn)
{
    char dn[256];
    int  rc = 0, tries = 0;

    tus_check_conn();
    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_delete_ext_s(ld, dn, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    /* audit log */
    if (rc == LDAP_SUCCESS) {
      audit_log("delete_token", userid, cn);
    }

    return rc;
}

int delete_tus_general_db_entry (char *dn)
{
    int  rc = 0, tries = 0;

    tus_check_conn();

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_delete_ext_s(ld, dn, NULL, NULL)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

/**
 * delete_user_db_entry
 * Deletes user entry
 * params: agentid - user performing this change
 *         uid - user to be deleted
 * returns: LDAP return code
 */
TPS_PUBLIC int delete_user_db_entry(const char *agentid, char *uid)
{
    char dn[256];
    int rc =0;
    if (PR_snprintf(dn, 255, "uid=%s,ou=People,%s", uid, userBaseDN) < 0)
        return -1;
    rc = delete_tus_general_db_entry(dn);
    
    if (rc == LDAP_SUCCESS) {
        audit_log("delete user", agentid, uid);
    }

    return rc;
}


TPS_PUBLIC int find_tus_db_entry (char *cn, int max, LDAPMessage **result)
{
    char dn[256];
    int  rc = 0, tries = 0;

    tus_check_conn();
    if (ld == NULL)
      return -1;

    if (PR_snprintf(dn, 255, "cn=%s,%s", cn, baseDN) < 0)
        return -1;

    if (debug_fd)
      PR_fprintf(debug_fd, "find_tus_db_entry: looking for :%s\n",dn);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
      if (debug_fd)
	PR_fprintf(debug_fd, "find_tus_db_entry: tries = %d\n",tries);
        if ((rc = ldap_search_ext_s (ld, dn, LDAP_SCOPE_BASE, "(objectclass=*)",
                       NULL, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
	  if (debug_fd)
	    PR_fprintf(debug_fd, "find_tus_db_entry: found it\n");

            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
	  if (debug_fd)
	    PR_fprintf(debug_fd, "find_tus_db_entry: server down or connect error\n");
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        } else {/* can't find?*/
	  if (debug_fd)
	    PR_fprintf(debug_fd, "find_tus_db_entry: can't find\n");
	  break;
	}
    }

    return rc;
}

TPS_PUBLIC int find_tus_db_entries (const char *filter, int max, LDAPMessage **result)
{
    int  rc = LDAP_OTHER, tries = 0;

    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);
   
    ldap_create_sort_keylist(&sortKeyList, "-dateOfModify");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */, 
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, baseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

TPS_PUBLIC int find_tus_db_entries_pcontrol_1(const char *filter, int max, int time_limit, int size_limit, LDAPMessage **result)
{
    int  rc = LDAP_OTHER, tries = 0;

    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    struct berval *cookie=NULL;
    struct timeval timeout;

    timeout.tv_sec = time_limit;
    timeout.tv_usec = 0;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    rc = ldap_create_page_control(ld, max, cookie, 0, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfModify");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */,
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        rc = ldap_search_ext_s (ld, baseDN, LDAP_SCOPE_SUBTREE, filter,
                 NULL, 0, controls, NULL, 
                 time_limit >0 ? &timeout : NULL, 
                 size_limit, result);
        if ((rc == LDAP_SUCCESS) || (rc == LDAP_PARTIAL_RESULTS)) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    if (cookie != NULL) {
        ber_bvfree(cookie);
        cookie = NULL;
    }

    ldap_free_sort_keylist(sortKeyList);
    
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

static int sort_cmp(const char *v1, const char *v2)
{
  return PL_strcasecmp(v1, v2);
}

static int reverse_sort_cmp(const char *v1, const char *v2)
{
  return PL_strcasecmp(v2, v1);
}

typedef int (LDAP_SORT_AD_CMP_PROC) (const char * left, const char *right);
static LDAP_SORT_AD_CMP_PROC *et_cmp_fn;

struct entrything {
    char **et_vals;
    LDAPMessage *et_msg;
};

static int et_cmp(const void  *aa, const void  *bb)
{
    int i, rc;

    struct entrything *a = (struct entrything *)aa;
    struct entrything *b = (struct entrything *)bb;

    if ((a == NULL) && (b == NULL))
        return 0;
    if (a == NULL)
        return -1;
    if (b == NULL)
        return 1;

    if ((a->et_vals == NULL) && (b->et_vals == NULL))
        return 0;
    if (a->et_vals == NULL)
        return -1;
    if (b->et_vals == NULL)
        return 1;

    for ( i = 0; a->et_vals[i] && b->et_vals[i]; i++ ) {
        if ( (rc = (*et_cmp_fn)( a->et_vals[i], b->et_vals[i] )) != 0) {
            return rc;
        }
    }

    if ((a->et_vals[i] == NULL) && (b->et_vals[i] == NULL))
        return 0;
    if (a->et_vals[i] == NULL)
        return -1;
    return 1;
}


static int ldap_multisort_entries(LDAP *ld,  LDAPMessage **chain, char **attr, LDAP_SORT_AD_CMP_PROC *cmp)
{
    int i, count, c;
    struct entrything *et;
    LDAPMessage *e;

    if ((chain == NULL) || (cmp == NULL) || (attr == NULL)) {
        return LDAP_PARAM_ERROR;
    }

    count = ldap_count_entries( ld, *chain );

    if (count < 0) { /* error, usually with bad ld or malloc */
        return LDAP_PARAM_ERROR;
    }

    if (count < 2) { /* nothing to sort */
        return 0;
    }

    if ((et = (struct entrything *)PR_Malloc( count * sizeof(struct entrything) )) == NULL ) {
        //ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, LDAP_NO_MEMORY);
        return -1;
    }

    for (i=0, e=get_first_entry(*chain); e != NULL; e = get_next_entry(e)) {
        et[i].et_msg = e;
        et[i].et_vals = NULL;
        if (attr == NULL) {
            /* if attr =NULL, sort by dn -- not yet implemented , fixme.
               char *dn;
               LDAPDN *ldapdn;
               dn = ldap_get_dn(ld, e);
               ldapstr2dn(dn, ldapdn, LDAP_DN_FORMAT_LDAPV3|LDAP_DN_P_NO_SPACES);
               et[i].et_vals = ldap_explode_dn(dn, 1);
               ldap_memfree(dn); */
        } else {
            int attrcnt;
            struct berval **vals;

            for (attrcnt = 0; attr[attrcnt] != NULL; attrcnt++ ) {
                vals = ldap_get_values_len(ld, e, attr[attrcnt]);
                if (vals == NULL) {
                    continue;
                }
                for (c=0; vals[c] != NULL; c++); 
                et[i].et_vals = (char **) PR_Malloc((c+1) * sizeof(char *));
                for (c=0; vals[c] != NULL; c++) {
                    if (vals[c]->bv_val != NULL) {
                        et[i].et_vals[c] = (char *) PL_strdup(vals[c]->bv_val);
                    } else {
                        et[i].et_vals[c] = NULL;
                    }
                }
                et[i].et_vals[c] = NULL; 

                if (vals != NULL) {
                    ldap_value_free_len(vals );
                    vals = NULL;
                }
            }
        }
        i++;
    }

    et_cmp_fn = cmp;
    qsort((void *) et, (size_t) count, (size_t) sizeof(struct entrything), et_cmp);

    // reconstruct chain
    
    for (i=0; i< count-1; i++)
        ldap_delete_result_entry(chain, et[i].et_msg);

    for (i=count -2; i >=0; i--)
        ldap_add_result_entry(chain, et[i].et_msg); 

    // free et
    for (i= 0; i < count; i++) {
        for (c=0; et[i].et_vals[c] != NULL; c++) {
            PL_strfree( et[i].et_vals[c]);
            et[i].et_vals[c] = NULL;
        } 
    } 

    PR_Free( (char *) et );

    return 0;
}

/* this is not implemented in openldap and must be implemented in custom code.
 * This code is adopted from mozldap sort.c 
 */
static int ldap_sort_entries(LDAP *ld, LDAPMessage **result, const char* attr, LDAP_SORT_AD_CMP_PROC *cmp) 
{
    char    *attrs[2];
    attrs[0] = (char *) attr;
    attrs[1] = NULL;
    return ldap_multisort_entries(ld, result, attr ? attrs : NULL, cmp);
} 

TPS_PUBLIC int find_tus_token_entries_no_vlv(char *filter, LDAPMessage **result, int order) 
{
    int rc = LDAP_OTHER, tries = 0;

    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, baseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            /* we do client-side sorting here */
            if (order == 0) {
                rc = ldap_sort_entries(ld, result, "dateOfCreate", 
                                     sort_cmp); 
            } else { /* order == 1 */
                rc = ldap_sort_entries(ld, result, "dateOfCreate", 
                                     reverse_sort_cmp); 
            }
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }
    
    return rc;
}

/**
 * find_tus_user_entries_no_vlv
 * params: filter - ldap search filter
 *         result - hash of LDAP Search results.
 *         order  - 0 (order results increasing by uid), (!=0) order by decreasing uid
 */ 
TPS_PUBLIC int find_tus_user_entries_no_vlv(char *filter, LDAPMessage **result, int order)
{
    int rc = LDAP_OTHER, tries = 0;
    char peopleBaseDN[256];

    PR_snprintf(peopleBaseDN, 256, "ou=People,%s", userBaseDN);
    
    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, peopleBaseDN, LDAP_SCOPE_ONELEVEL, filter,
                       userAttributes, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            /* we do client-side sorting here */
            if (order == 0) {
                rc = ldap_sort_entries(ld, result, USER_ID, sort_cmp);
            } else {
                rc = ldap_sort_entries(ld, result, USER_ID, reverse_sort_cmp);
            }
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

/**
 * find_tus_user_role_entries
 * summary: return the dns for the groups to which the user belongs
 *        (TUS Administrators, Agents, Operator)
 * params: uid - userid
 *         result - hash of LDAPResults
 */
TPS_PUBLIC int find_tus_user_role_entries( const char*uid, LDAPMessage **result) 
{
    int rc = LDAP_OTHER, tries = 0;
    char groupBaseDN[256];
    char filter[256];
    char *subgroup_attrs[] = {SUBGROUP_ID, NULL};
 
    PR_snprintf(groupBaseDN, 256, "ou=Groups,%s", userBaseDN);
    PR_snprintf(filter, 256, "member=uid=%s,ou=People,%s", uid, userBaseDN);

    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, groupBaseDN, LDAP_SCOPE_SUBTREE, filter,
            subgroup_attrs, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

TPS_PUBLIC int find_tus_activity_entries_no_vlv(char *filter, LDAPMessage **result, int order)
{
    int rc = LDAP_OTHER, tries = 0;

    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, activityBaseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            /* we do client-side sorting here */
            if (order == 0) {
              rc = ldap_sort_entries(ld, result, "dateOfCreate", 
                                     sort_cmp);
            } else { /* order == 1 */
              rc = ldap_sort_entries(ld, result, "dateOfCreate",
                                     reverse_sort_cmp);
            }
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

TPS_PUBLIC int find_tus_token_entries(char *filter, int max, LDAPMessage **result, int order) 
{
    int rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
     (*sortKeyList)->reverseOrder = order;
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */,
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, baseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }
    
    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

TPS_PUBLIC int update_token_status_reason_userid(const char *userid, char *cuid,
  const char *tokenStatus, const char *reason, int modifyDateOfCreate) {
    LDAPMod **mods = NULL;
    int status;
    char **v = NULL;
    int len = 0;

    tus_check_conn();
    if (modifyDateOfCreate)
        mods = allocate_modifications(5);
    else
        mods = allocate_modifications(4);

    if (mods == NULL) {
        return -1;
    } else {
        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
    }
    
    mods[0]->mod_op = LDAP_MOD_REPLACE;
    mods[0]->mod_type = get_modification_date_name();
    mods[0]->mod_values = v; 

    /* for token status */
    if (tokenStatus != NULL && PL_strlen(tokenStatus) > 0) {
        len = PL_strlen(tokenStatus);
        if ((v = allocate_values(1, len+1)) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
        PL_strcpy(v[0], tokenStatus);
        mods[1]->mod_op = LDAP_MOD_REPLACE;
        mods[1]->mod_type = get_token_status_name();
        mods[1]->mod_values = v;
    }
  
    /* for token reason */
    if (reason != NULL && PL_strlen(reason) > 0)
        len = PL_strlen(reason);
    else 
        len = 0;
    if ((v = allocate_values(1, len+1)) == NULL) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return -1;
    }
    mods[2]->mod_op = LDAP_MOD_REPLACE;
    mods[2]->mod_type = tokenAttributes[13];
    if (reason != NULL && PL_strlen(reason) > 0)
        PL_strcpy(v[0], reason);
    else
        v[0] = "";
    mods[2]->mod_values = v;

    /* for userid */
    if (userid != NULL && PL_strlen(userid) > 0)
        len = PL_strlen(userid);
    else
        len = 0;
    if ((v = allocate_values(1, len+1)) == NULL) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return -1;
    }
    mods[3]->mod_op = LDAP_MOD_REPLACE;
    mods[3]->mod_type = "tokenUserID";
    if (userid != NULL && PL_strlen(userid) > 0)
        PL_strcpy(v[0], userid);
    else
        v[0] = "";
    mods[3]->mod_values = v;

    if (modifyDateOfCreate) {
        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
    
        mods[4]->mod_op = LDAP_MOD_REPLACE;
        mods[4]->mod_type = "dateOfCreate";
        mods[4]->mod_values = v; 

    }

    status = update_tus_db_entry_with_mods(userid, cuid, mods);
    return status;
}

TPS_PUBLIC int update_token_status_reason(char *userid, char *cuid, const char *tokenStatus, const char *reason) {
    LDAPMod **mods = NULL;
    int status;
    char **v = NULL;
    int len = 0;
    
    tus_check_conn();
    mods = allocate_modifications(3);

    if (mods == NULL) {
        return -1;    
    } else {
        if ((v = create_modification_date_change()) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
    }

    mods[0]->mod_op = LDAP_MOD_REPLACE;
    mods[0]->mod_type = get_modification_date_name();
    mods[0]->mod_values = v;

    /* for token status */
    if (tokenStatus != NULL && PL_strlen(tokenStatus) > 0) {
        len = PL_strlen(tokenStatus);
        if ((v = allocate_values(1, len+1)) == NULL) {
            if( mods != NULL ) {
                free_modifications( mods, 0 );
                mods = NULL;
            }
            return -1;
        }
        PL_strcpy(v[0], tokenStatus);
        mods[1]->mod_op = LDAP_MOD_REPLACE;
        mods[1]->mod_type = get_token_status_name();
        mods[1]->mod_values = v;
    }

    /* for token reason */
    if (reason != NULL && PL_strlen(reason) > 0)
        len = PL_strlen(reason);
    else
        len = 0;
    if ((v = allocate_values(1, len+1)) == NULL) {
        if( mods != NULL ) {
            free_modifications( mods, 0 );
            mods = NULL;
        }
        return -1;
    }
    mods[2]->mod_op = LDAP_MOD_REPLACE;
    mods[2]->mod_type = tokenAttributes[13];
    if (reason != NULL && PL_strlen(reason) > 0)
        PL_strcpy(v[0], reason);
    else
        v[0] = "";
    mods[2]->mod_values = v;

    status = update_tus_db_entry_with_mods(userid, cuid, mods);
    return status;
}

TPS_PUBLIC int tus_has_active_tokens(char *userid)
{
    LDAPMessage *result;
    char filter[256];
    int n = 0;

    int rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;
    int max = 1000;
    
    tus_check_conn();
    PR_snprintf(filter, 256, "(&(tokenStatus=active)(tokenUserID=%s))", userid);
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */,
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, baseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, &result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((n = ldap_count_entries (ld, result)) >= 0) {
            break;
        } else {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    if (rc == LDAP_SUCCESS) {
        if (n > 0)
            return 0;
        else
            return -1;
    }

    return rc;
}

TPS_PUBLIC int find_tus_certificate_entries_by_order_no_vlv (char *filter, 
  LDAPMessage **result, int order)
{   
    int  rc = LDAP_OTHER, tries = 0;

    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, certBaseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, NULL, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            /* we do client-side sorting here */
            if (order == 0) {
              rc = ldap_sort_entries(ld, result, "dateOfCreate", 
                                   sort_cmp);
            } else {
              rc = ldap_sort_entries(ld, result, "dateOfCreate", 
                                   reverse_sort_cmp);
            }
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential; 
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);  
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return rc;
}

TPS_PUBLIC int find_tus_certificate_entries_by_order (char *filter, int max, 
  LDAPMessage **result, int order)
{   
    int  rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;
                       
    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;
            
    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
    (*sortKeyList)->reverseOrder = order;
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */,
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, certBaseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential; 
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);  
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

int find_tus_certificate_entries (char *filter, int max, LDAPMessage **result)
{
    int  rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */, 
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, certBaseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

int find_tus_activity_entries (char *filter, int max, LDAPMessage **result)
{
    int  rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    LDAPVLVInfo vlv_data;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    vlv_data.ldvlv_before_count = 0;
    vlv_data.ldvlv_after_count = max - 1;
    vlv_data.ldvlv_attrvalue = NULL;
    vlv_data.ldvlv_count = max;
    vlv_data.ldvlv_offset = 0;
    vlv_data.ldvlv_version = 1; 
    vlv_data.ldvlv_context = NULL;
    vlv_data.ldvlv_extradata = NULL;
    ldap_create_vlv_control(ld, &vlv_data, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */, 
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((rc = ldap_search_ext_s (ld, activityBaseDN, LDAP_SCOPE_SUBTREE, filter,
                       NULL, 0, controls, NULL, NULL, 0, result)) == LDAP_SUCCESS) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    ldap_free_sort_keylist(sortKeyList);
    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

TPS_PUBLIC int find_tus_activity_entries_pcontrol_1(char *filter, int max, int time_limit, int size_limit, LDAPMessage **result)
{
    int  rc = LDAP_OTHER, tries = 0;
    LDAPSortKey **sortKeyList;
    LDAPControl *controls[3];
    struct berval *cookie=NULL;
    struct timeval timeout;

    timeout.tv_sec = time_limit;
    timeout.tv_usec = 0;

    tus_check_conn();
    controls[0] = NULL;
    controls[1] = NULL;
    controls[2] = NULL;

    rc = ldap_create_page_control(ld, max, cookie, 0, &controls[0]);

    ldap_create_sort_keylist(&sortKeyList, "-dateOfCreate");
    ldap_create_sort_control(ld, sortKeyList, 1 /* non-critical */,
        &controls[1]);

    for (tries = 0; tries < MAX_RETRIES; tries++) {
        rc = ldap_search_ext_s (ld, activityBaseDN, LDAP_SCOPE_SUBTREE, filter,
                 NULL, 0, controls, NULL,
                 time_limit >0 ? &timeout : NULL,
                 size_limit, result);
        if ((rc == LDAP_SUCCESS) || (rc == LDAP_PARTIAL_RESULTS)) {
            break;
        } else if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    if (cookie != NULL) {
       ber_bvfree(cookie);
       cookie = NULL;
    }

    ldap_free_sort_keylist(sortKeyList);

    ldap_control_free(controls[0]);
    ldap_control_free(controls[1]);

    return rc;
}

int get_number_of_entries (LDAPMessage *result)
{
    int  n = 0, rc = 0, tries = 0;

    tus_check_conn();
    for (tries = 0; tries < MAX_RETRIES; tries++) {
        if ((n = ldap_count_entries (ld, result)) >= 0) {
            break;
        } else {
            struct berval credential;
            credential.bv_val = bindPass;
            credential.bv_len= strlen(bindPass);
            rc = ldap_sasl_bind_s(ld, bindDN, LDAP_SASL_SIMPLE, &credential, NULL, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                bindStatus = rc;
                break;
            }
        }
    }

    return n;
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

CERTCertificate **get_certificates(LDAPMessage *entry) {
    int i;    
    struct berval **bvals;
    CERTCertificate *cert;
    int c = 0;
    CERTCertificate **ret = NULL;

    tus_check_conn();
    bvals = ldap_get_values_len(ld, entry, "userCertificate");
    if (bvals == NULL)
        return NULL;

    for (i = 0; bvals[i] != NULL; i++ )
        c++;    
    ret = (CERTCertificate **) malloc ((sizeof (CERTCertificate *) * c) + 1);
    c = 0;
    for (i = 0; bvals[i] != NULL; i++ ) {
        cert = CERT_DecodeCertFromPackage((char *) bvals[i]->bv_val, (int) 
          ( bvals[i]->bv_len ) );
        ret[c] = cert;
	c++;
    }  
    ret[c] = NULL;
    return ret;
   
}

struct berval **get_attribute_values(LDAPMessage *entry, const char *attribute)
{
    int i;
    unsigned int j;
    struct berval **bvals = NULL;
    char buffer[2048];
    int c = 0;
    struct berval **ret = NULL;

    tus_check_conn();
    if (PL_strcasecmp(attribute, "userCertificate") == 0) {
        bvals = ldap_get_values_len(ld, entry, attribute);
        if (bvals == NULL)
            return NULL;
        for (i = 0; bvals[i] != NULL; i++ ) {
	    c++;
        }  
        ret = (struct berval **) malloc ((sizeof (struct berval *) * c) + 1);

        ret = (struct berval **) calloc (sizeof (struct berval *), (c + 1));
        for (i=0; i< c; i++) {
            ret[i] = (struct berval *) malloc(sizeof(struct berval));
        }
        ret[c] = NULL;
        c = 0;
        for (i = 0; bvals[i] != NULL; i++ ) {
            char *tmp = BTOA_DataToAscii((unsigned char *)bvals[i]->bv_val,
                                         (int)bvals[i]->bv_len);
            snprintf(buffer, 2048, "%s", tmp); 
            PORT_Free(tmp);

            /* remove \r\n that javascript does not like */
            for (j = 0; j < strlen(buffer); j++) {
                if (buffer[j] == '\r') {
                    buffer[j] = '.';
                }
                if (buffer[j] == '\n') {
                    buffer[j] = '.';
                }
            }
	    ret[c]->bv_val = PL_strdup(buffer);
            ret[c]->bv_len = PL_strlen(buffer);
	    c++;
        }  
        if (bvals != NULL) {
            ldap_value_free_len(bvals);
            bvals = NULL;
        }

        return ret;
    } else {
        return ldap_get_values_len(ld, entry, attribute);
    }
}

void free_values(struct berval **values, int ldapValues)
{
    if (ldapValues != 0) {
        if( values != NULL ) {
            ldap_value_free_len( values );
            values = NULL;
        }
    } else {
        if( values != NULL ) {
            PR_Free( values );
            values = NULL;
        }
    }
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


TPS_PUBLIC char *get_token_reason(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenReason");
}

char *get_token_id(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, TOKEN_ID);
}

char *get_cert_tokenType(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenType");
}

char *get_cert_serial(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenSerial");
}

char *get_cert_type(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenKeyType");
}

char *get_cert_status(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "tokenStatus");
}

char *get_cert_issuer(LDAPMessage *entry) {
    return get_cert_attr_byname(entry, "tokenIssuer");
}

char *get_cert_cn(LDAPMessage *entry)
{
    return get_cert_attr_byname(entry, "cn");
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

char *get_number_of_modifications_name()
{
    return tokenAttributes[I_TOKEN_MODS];
}

int get_number_of_modifications(LDAPMessage *entry)
{
    return get_cert_attr_byname_int(entry, TOKEN_MODS);
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

char *get_number_of_resets_name()
{
    return tokenAttributes[I_TOKEN_RESETS];
}

int get_number_of_resets(LDAPMessage *entry)
{
    return get_cert_attr_byname_int(entry, TOKEN_RESETS);
}

char *get_number_of_enrollments_name()
{
    return tokenAttributes[I_TOKEN_ENROLLMENTS];
}

int get_number_of_enrollments(LDAPMessage *entry)
{
    return get_cert_attr_byname_int(entry, TOKEN_ENROLLMENTS);
}

char *get_number_of_renewals_name()
{
    return tokenAttributes[I_TOKEN_RENEWALS];
}

int get_number_of_renewals(LDAPMessage *entry)
{
    return get_cert_attr_byname_int(entry, TOKEN_RENEWALS);
}

char *get_number_of_recoveries_name()
{
    return tokenAttributes[I_TOKEN_RECOVERIES];
}

int get_number_of_recoveries(LDAPMessage *entry)
{
    return get_cert_attr_byname_int(entry, TOKEN_RECOVERIES);
}

TPS_PUBLIC char *get_token_userid(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    char *ret = NULL;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if ((v = ldap_get_values_len(ld, e, TOKEN_USER)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                            ret = PL_strdup(v[0]->bv_val);
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return ret;
}

TPS_PUBLIC char *get_token_policy(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    char *ret = NULL;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry(cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if ((v = ldap_get_values_len(ld, e, TOKEN_POLICY)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                            ret = PL_strdup(v[0]->bv_val);
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return ret;
}

TPS_PUBLIC int allow_token_enroll_policy(char *cn, const char *policy)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    int can_reenroll = 0;
    int token_is_uninitialized = 0;
    int is_reenroll_attempt = 0;
    int rc = -1;
    char *token_status = NULL;

    if(PL_strstr(policy,"RE_ENROLL"))
        is_reenroll_attempt = 1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if(is_reenroll_attempt) {
                    token_status = get_token_status(e);

                    if(token_status && PL_strcmp(token_status,STATE_UNINITIALIZED) == 0)
                        token_is_uninitialized = 1;

                    if(token_status)  {    
                        PR_Free(token_status);
                        token_status = NULL;
                    }
                }

                if ((v = ldap_get_values_len(ld, e, TOKEN_POLICY)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                        if (PL_strstr(v[0]->bv_val, policy)) {
                            can_reenroll = 1;
                        }  else  {
                            if( is_reenroll_attempt && token_is_uninitialized)  {
                                can_reenroll = 1;
                            }
                        }
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return can_reenroll;
}

TPS_PUBLIC int allow_token_renew(char *cn)
{
    return allow_token_enroll_policy(cn, "RENEW=YES");
}

TPS_PUBLIC int allow_token_reenroll(char *cn)
{
    return allow_token_enroll_policy(cn, "RE_ENROLL=YES");
}

TPS_PUBLIC int force_token_format(char *cn)
{
    return allow_token_enroll_policy(cn,"FORCE_FORMAT=YES");
}

TPS_PUBLIC int is_token_present(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    int present = 0;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                present = 1;
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return present;
}

TPS_PUBLIC int is_token_pin_resetable(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    int resetable = 1;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if ((v = ldap_get_values_len(ld, e, TOKEN_POLICY)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                        if (PL_strstr(v[0]->bv_val, "PIN_RESET=NO")) {
                            resetable = 0;
                        }
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return resetable;
}

TPS_PUBLIC int is_update_pin_resetable_policy(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    int resetable = 0;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if ((v = ldap_get_values_len(ld, e, TOKEN_POLICY)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                        if (PL_strstr(v[0]->bv_val, "RESET_PIN_RESET_TO_NO=YES")) {
                            resetable = 1;
                        }
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return resetable;
}

TPS_PUBLIC int is_tus_db_entry_disabled(char *cn)
{
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    struct berval **v = NULL;
    int disabled = 1;
    int rc = -1;

    if (cn != NULL && PL_strlen(cn) > 0) {
        if ((rc = find_tus_db_entry (cn, 0, &result)) == LDAP_SUCCESS) {
            e = get_first_entry (result);
            if (e != NULL) {
                if ((v = ldap_get_values_len(ld, e, TOKEN_STATUS)) != NULL) {
                    if ((valid_berval(v)) && (PL_strlen(v[0]->bv_val) > 0)) {
                        if (!PL_strcasecmp(v[0]->bv_val, STATE_ACTIVE) ||
                            !PL_strcasecmp(v[0], STATE_UNINITIALIZED)) {
                            disabled = 0;
                        }
                    }
                    if( v != NULL ) {
                        ldap_value_free_len( v );
                        v = NULL;
                    }
                }
            }
            if( result != NULL ) {
                free_results( result );
                result = NULL;
            }
        }
    }
    return disabled;
}

TPS_PUBLIC LDAPMod **allocate_modifications(int size)
{
    int i, n;
    LDAPMod **mods = NULL;
    char *s;

    n = ((size + 1) * sizeof(LDAPMod *)) + (size * sizeof(LDAPMod));
    s = (char *) PR_Malloc(n);
    if (s == NULL)
        return NULL;
    memset(s, 0, n);

    mods = (LDAPMod **)s;

    s += ((size + 1) * sizeof(LDAPMod *));

    for (i = 0; i < size; i++) {
        mods[i] = (LDAPMod *)s;
        s += sizeof(LDAPMod);
    }

    return mods;
}

void free_modifications(LDAPMod **mods, int ldapValues)
{
    int i;

    if( mods == NULL ) {
        return;
    }

    if (ldapValues) {
        ldap_mods_free(mods, 0);
        return;
    }

    for (i = 0; mods[i] != NULL; i++) {
        if ((mods[i]->mod_op & LDAP_MOD_BVALUES) &&
            (mods[i]->mod_bvalues != NULL)) {
            if( ( mods[i] != NULL ) && ( mods[i]->mod_bvalues != NULL ) ) {
                PR_Free( mods[i]->mod_bvalues );
                mods[i]->mod_bvalues = NULL;
            }
        } else if (mods[i]->mod_values != NULL) {
            if( ( mods[i] != NULL ) && ( mods[i]->mod_values != NULL ) ) {
                PR_Free( mods[i]->mod_values );
                mods[i]->mod_values = NULL;
            }
        }
    }
    if( mods != NULL ) {
        PR_Free( mods );
        mods = NULL;
    }
}

TPS_PUBLIC char **allocate_values(int size, int extra)
{
    int  n;
    char **values = NULL;
    char *s;

    n = (size + 1) * sizeof(char *);
    if (extra > 0) {
        n += extra * sizeof(char);
    }
    s = (char *) PR_Malloc(n);
    if (s == NULL)
        return NULL;
    memset(s, 0, n);

    values = (char **)s;

    if (extra > 0) {
        s += ((size + 1) * sizeof(char *));
        values[0] = s;
    }

    return values;
}

TPS_PUBLIC char **create_modification_date_change()
{
    PRExplodedTime time;
    PRTime now;
    char **v = NULL;

    if ((v = allocate_values(1, 16)) == NULL) {
        return NULL;
    }

    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);

    PR_snprintf(v[0], 16, "%04d%02d%02d%02d%02d%02dZ",
                time.tm_year, (time.tm_month + 1), time.tm_mday,
                time.tm_hour, time.tm_min, time.tm_sec);

    return v;
}

/**
 * Reads password.conf file
 */
static int ReadLine(PRFileDesc *f, char *buf, int buf_len, int *removed_return)
{
       char *cur = buf;
       int sum = 0;
       PRInt32 rc;

       *removed_return = 0;
       while (1) {
         rc = PR_Read(f, cur, 1);
         if (rc == -1 || rc == 0)
             break;
         if (*cur == '\r') {
             continue;
         }
         if (*cur == '\n') {
             *cur = '\0';
             *removed_return = 1;
             break;
         }
         sum++;
         cur++;
       }
       return sum;
}

#define MAX_CFG_LINE_LEN 4096
/*
 * Search for password name "name" in the password file "filepath"
 */
char *get_pwd_from_conf(char *filepath, char *name)
{
    PRFileDesc *fd;
    char line[MAX_CFG_LINE_LEN];
    int removed_return;
    char *val= NULL;

    if (debug_fd)
	    PR_fprintf(debug_fd, "get_pwd_from_conf looking for %s\n", name);
    fd= PR_Open(filepath, PR_RDONLY, 400);
    if (fd == NULL) {
        return NULL;
    }
    if (debug_fd)
	    PR_fprintf(debug_fd, "get_pwd_from_conf opened %s\n", filepath);

    while (1) {
        int n = ReadLine(fd, line, MAX_CFG_LINE_LEN, &removed_return);
        if (n > 0) {
            /* handle comment line */
            if (line[0] == '#')
                continue;
            int c = 0;
            while ((c < n) && (line[c] != ':')) {
                c++;
            }
            if (c < n) {
                line[c] = '\0';
            } else {
                continue; /* no ':', skip this line */
            }
            if (!PL_strcmp (line, name)) {
                if (debug_fd)
	              PR_fprintf(debug_fd, "get_pwd_from_conf found %s is %s\n", line, &line[c+1]);
                val =  PL_strdup(&line[c+1]);
                break;
            }
        } else if (n == 0 && removed_return == 1) {
            continue; /* skip empty line */
        } else {
            break;
        }
    }
    if( fd != NULL ) {
        PR_Close( fd );
        fd = NULL;
    }
    return val;

}

void audit_log(const char *func_name, const char *userid, const char *msg)
{
    const char* time_fmt = "%Y-%m-%d %H:%M:%S";
    char datetime[1024];
    PRTime now;
    PRExplodedTime time;
    PRThread *ct;

    if (audit_fd == NULL)
        return;

    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    ct = PR_GetCurrentThread();
    PR_fprintf(audit_fd, "[%s] t=%x uid=%s op=%s - ", 
	datetime, ct, userid, func_name);
    PR_fprintf(audit_fd, "%s", msg);
    PR_fprintf(audit_fd, "\n");
}

int base64_decode( char *src, unsigned char *dst )
{

#define RIGHT2            0x03
#define RIGHT4            0x0f

         unsigned char b642nib[0x80] = {
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
         0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
         0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
         0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
         0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
         0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
         0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
         0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
         0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
         };
         char            *p, *stop;
         unsigned char   nib, *byte;
         int             i, len;
 
         stop = strchr( src, '\0' );
         byte = dst;
         for ( p = src, len = 0; p < stop; p += 4, len += 3 ) {
                 for ( i = 0; i < 4; i++ ) {
                         if ( p[i] != '=' && (p[i] & 0x80 ||
                             b642nib[ p[i] & 0x7f ] > 0x3f) ) {
                                 return( -1 );
                         }
                 }
 
                 /* first digit */
                 nib = b642nib[ p[0] & 0x7f ];
                 byte[0] = nib << 2;
 
                 /* second digit */
                 nib = b642nib[ p[1] & 0x7f ];
                 byte[0] |= nib >> 4;
 
                 /* third digit */
                 if ( p[2] == '=' ) {
                         len += 1;
                         break;
                 }
                 byte[1] = (nib & RIGHT4) << 4;
                 nib = b642nib[ p[2] & 0x7f ];
                 byte[1] |= nib >> 2;
 
                 /* fourth digit */
                 if ( p[3] == '=' ) {
                         len += 2;
                         break;
                 }
                 byte[2] = (nib & RIGHT2) << 6;
                 nib = b642nib[ p[3] & 0x7f ];
                 byte[2] |= nib;
 
                 byte += 3;
         }
 
         return( len );
}

