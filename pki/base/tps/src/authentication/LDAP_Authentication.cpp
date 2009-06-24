// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "engine/RA.h"
#include "ldap.h"
#include "ldap_ssl.h"
#include "ldappr.h"
#include "authentication/LDAP_Authentication.h"
#include "authentication/Authentication.h"
#include "main/Memory.h"
#include "main/Util.h"

/**
 * Constructs a base processor.
 */
LDAP_Authentication::LDAP_Authentication ()
{
    m_hostport = NULL;
    m_baseDN = NULL;
    m_connInfo = NULL;
    m_attributes = NULL;
    m_ssl = NULL;
    m_bindDN = NULL;
    m_bindPwd = NULL;
}

/**
 * Destructs processor.
 */
LDAP_Authentication::~LDAP_Authentication ()
{
    if( m_hostport != NULL ) {
        PL_strfree( m_hostport );
        m_hostport = NULL;
    }

    if( m_baseDN != NULL ) {
        PL_strfree( m_baseDN );
        m_baseDN = NULL;
    }

    if( m_connInfo != NULL ) {
        delete m_connInfo;
        m_connInfo = NULL;
    }
}

/*
 * Search for password name "name" in the password file "filepath"
 */
static char *get_pwd_from_conf(char *filepath, char *name)
{
    PRFileDesc *fd;
    char line[1024];
    int removed_return;
    char *val= NULL;

    fd= PR_Open(filepath, PR_RDONLY, 400);
    if (fd == NULL) {
        return NULL;
    }

    while (1) {
        int n = Util::ReadLine(fd, line, 1024, &removed_return);
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

void LDAP_Authentication::Initialize(int instanceIndex) {
    char configname[256];
    const char *prefix="auth.instance";
    
    m_index = instanceIndex;
    PR_snprintf((char *)configname, 256, "%s.%d.hostport", prefix, instanceIndex);
    m_hostport = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.SSLOn", prefix, instanceIndex);
    m_isSSL = RA::GetConfigStore()->GetConfigAsBool(configname, true);
    PR_snprintf((char *)configname, 256, "%s.%d.retries", prefix, instanceIndex);
    m_retries = RA::GetConfigStore()->GetConfigAsInt(configname, 1);
    PR_snprintf((char *)configname, 256, "%s.%d.retryConnect", prefix, instanceIndex);
    m_connectRetries = RA::GetConfigStore()->GetConfigAsInt(configname, 3);
    m_connInfo = new ConnectionInfo();
    m_connInfo->BuildFailoverList(m_hostport);
    PR_snprintf((char *)configname, 256, "%s.%d.baseDN", prefix, instanceIndex);
    m_baseDN = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.attributes", prefix, instanceIndex);
    m_attributes = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    /* support of SSL */
    PR_snprintf((char *)configname, 256, "%s.%d.ssl", prefix, instanceIndex);
    m_ssl = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.bindDN", prefix, instanceIndex);
    m_bindDN = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    PR_snprintf((char *)configname, 256, "%s.%d.bindPWD", prefix, instanceIndex);
    char *m_bindPwdPath = PL_strdup(RA::GetConfigStore()->GetConfigAsString(configname));
    m_bindPwd = get_pwd_from_conf(m_bindPwdPath, "tokendbBindPass");
}

/**
 * @return (0:login correct) (-1:LDAP error)  (-2:User not found) (-3:Password error)
 */

#define TPS_AUTH_OK                       0
#define TPS_AUTH_ERROR_LDAP              -1
#define TPS_AUTH_ERROR_USERNOTFOUND      -2
#define TPS_AUTH_ERROR_PASSWORDINCORRECT -3

int LDAP_Authentication::Authenticate(AuthParams *params)
{
    char buffer[500];
    char *host = NULL;
    char *portStr = NULL;
    int port = 0;
    LDAP *ld = NULL;
    int status = TPS_AUTH_ERROR_LDAP;
    int version = LDAP_VERSION3;
    LDAPMessage *result, *e;
    char *dn = NULL;
    char *uid = NULL;
    char *password = NULL;
    int retries = 0;

    if (params == NULL) {
        status = TPS_AUTH_ERROR_USERNOTFOUND;
        goto loser;
    }

    uid = params->GetUID();
    password = params->GetPassword();

    GetHostPort(&host, &portStr);
    port = atoi(portStr); 

    if (m_ssl != NULL & strcmp(m_ssl, "true")==0) {
      /* handling of SSL */
      ld = ldapssl_init(host, port, 1); 
    } else {
      /* NOTE:  ldapssl_init() already utilizes */
      /*        prldap (IPv6) functionality.    */
      ld = prldap_init(host, port, 1); 
    }
    while (ld == NULL && retries < m_connectRetries) {
        RA::IncrementAuthCurrentIndex(m_connInfo->GetHostPortListLen());
        GetHostPort(&host, &portStr);
        port = atoi(portStr);
        ld = prldap_init(host, port, 1); 
        retries++;    
    }

    if (ld == NULL) {
        status = TPS_AUTH_ERROR_LDAP;
        goto loser;
    }

    if (ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
        status = TPS_AUTH_ERROR_LDAP;
        goto loser;    
    }
        
    if (m_bindDN != NULL && strlen(m_bindDN) > 0) {
      RA::Debug("LDAP_Authentication::Authenticate", "Simple bind required '%s'", m_bindDN);
      ldap_simple_bind_s(ld, m_bindDN, m_bindPwd);
    }

    PR_snprintf((char *)buffer, 500, "(uid=%s)", uid);
    if (ldap_search_s(ld, m_baseDN, LDAP_SCOPE_SUBTREE, buffer, NULL, 0, &result) != LDAP_SUCCESS) {
        status = TPS_AUTH_ERROR_USERNOTFOUND;
        goto loser; 
    } else {
        for (e = ldap_first_entry(ld, result); e != NULL; e = ldap_next_entry(ld, e)) {
            if ((dn = ldap_get_dn(ld, e)) != NULL) {
RA::Debug("LDAP_Authentication::Authenticate", "User bind required '%s' '(sensitive)'", dn );
                if (ldap_simple_bind_s(ld, dn, password) == LDAP_SUCCESS) {
                    /* retrieve attributes and, */
                    /* put them into the auth parameters */
                    if (m_attributes != NULL) { 
                         RA::Debug("LDAP_Authentication::Authenticate", "Attributes %s", m_attributes);
                         char *m_dup_attributes = strdup(m_attributes);
                         char *token = NULL; 
                         token = strtok(m_dup_attributes, ","); 
                         while( token != NULL ) { 
                             char **v = NULL;
                             v = ldap_get_values(ld, e, token);
                             if (v != NULL) {
                                 RA::Debug("LDAP_Authentication::Authenticate", "Exposed %s=%s", token, v[0]);
                                 params->Add(token, PL_strdup(v[0]));
                                 RA::Debug("LDAP_Authentication::Authenticate", "Size %d", params->Size());
                             }
                             token = strtok( NULL, "," ); 
                             if( v != NULL ) {
                                 ldap_value_free( v );
                                 v = NULL;
                             }

                         }
						 free(m_dup_attributes);
                    }
					status = TPS_AUTH_OK;   // SUCCESS - PASSWORD VERIFIED
				} else {
                    status = TPS_AUTH_ERROR_PASSWORDINCORRECT;
                    goto loser;
                } 
            } else {
                status = TPS_AUTH_ERROR_USERNOTFOUND;
                goto loser;
            } 
        }
    }

    if (dn == NULL) {
        status = TPS_AUTH_ERROR_USERNOTFOUND;
        goto loser;
    }

loser:

    if (result != NULL) {
      ldap_msgfree(result);
    }

    if (dn != NULL) {
      ldap_memfree(dn);
    }

    if (ld != NULL) {
        ldap_unbind(ld);
        ld = NULL;
    } 
    return status;
}

void LDAP_Authentication::GetHostPort(char **p, char **q) {
    int num=0;
    int auth_curr = RA::GetAuthCurrentIndex();
    char *hp = (m_connInfo->GetHostPortList())[auth_curr];
    char *host_port = PL_strdup(hp);

    char *lasts = NULL;
    char *tok = PL_strtok_r((char *)host_port, ":", &lasts);
    while (tok != NULL) {
        if (num == 0)
            *p = PL_strdup(tok);
        else
            *q = PL_strdup(tok);
        tok = PL_strtok_r(NULL, ":", &lasts);
        num++;
    } 

    PR_Free(host_port);
} 

bool LDAP_Authentication::IsSSL() {
    return m_isSSL;
}

char *LDAP_Authentication::GetHostPort() {
    return m_hostport;
}

Authentication *GetAuthentication() {
    LDAP_Authentication *auth = new LDAP_Authentication();    
    return (Authentication *)auth;
}

const char *LDAP_Authentication::GetTitle(char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.title.%s", 
        prefix, m_index, locale);
RA::Debug("LDAP_Authentication::GetTitle", "%s", configname);
    return RA::GetConfigStore()->GetConfigAsString(configname);
}

const char *LDAP_Authentication::GetDescription(char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.description.%s", 
        prefix, m_index, locale);
RA::Debug("LDAP_Authentication::GetDescription", "%s", configname);
RA::Debug("LDAP_Authentication::GetDescription", "%s", RA::GetConfigStore()->GetConfigAsString(configname));
    return RA::GetConfigStore()->GetConfigAsString(configname);
}

int LDAP_Authentication::GetNumOfParamNames()
{
    return 2;
}
                                                                                
char *LDAP_Authentication::GetParamID(int index)
{
    if (index == 0) 
        return ( char * ) "UID";
    else if (index == 1)
        return ( char * ) "PASSWORD";
    else
        return NULL;
}

const char *LDAP_Authentication::GetParamName(int index, char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.id.%s.name.%s", 
        prefix, m_index, GetParamID(index), locale);

RA::Debug("LDAP_Authentication::GetParamName", "%s", configname);

    return RA::GetConfigStore()->GetConfigAsString(configname);
}
                                                                                
char *LDAP_Authentication::GetParamType(int index)
{
    if (index == 0) 
        return ( char * ) "string";
    else if (index == 1)
        return ( char * ) "password";
    else
        return NULL;
}
                                                                                
const char *LDAP_Authentication::GetParamDescription(int index, char *locale)
{
    char configname[256];
    const char *prefix="auth.instance";
    PR_snprintf((char *)configname, 256, "%s.%d.ui.id.%s.description.%s", 
        prefix, m_index, GetParamID(index), locale);
    return RA::GetConfigStore()->GetConfigAsString(configname);
}
                                                                                
char *LDAP_Authentication::GetParamOption(int index)
{
    return ( char * ) "";
}

