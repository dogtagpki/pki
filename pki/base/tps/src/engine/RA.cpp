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

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "plhash.h"
#include "pk11func.h"
#include "cert.h"
#include "tus/tus_db.h"
#include "secder.h"
#include "nss.h"

#ifdef __cplusplus
}
#endif

#include "main/Memory.h"
#include "main/ConfigStore.h"
#include "main/RA_Context.h"
#include "channel/Secure_Channel.h"
#include "engine/RA.h"
#include "main/Util.h"
#include "cms/HttpConnection.h"
#include "main/RA_pblock.h"


static ConfigStore *m_cfg = NULL;
static PRFileDesc *m_fd_debug = (PRFileDesc *)NULL;
static PRFileDesc *m_fd_audit = (PRFileDesc *)NULL;
static PRFileDesc *m_fd_error = (PRFileDesc *)NULL;

static int tokendbInitialized = 0;

bool RA::m_pod_enable=false;
int RA::m_pod_curr = 0;
PRLock *RA::m_pod_lock = NULL;
int RA::m_auth_curr;
PRLock *RA::m_verify_lock = NULL;
PRLock *RA::m_auth_lock = NULL;
PRLock *RA::m_debug_log_lock = NULL;
PRLock *RA::m_error_log_lock = NULL;
PRLock *RA::m_audit_log_lock = NULL;
SecurityLevel RA::m_global_security_level;

int RA::m_audit_log_level = (int) LL_PER_SERVER;
int RA::m_debug_log_level = (int) LL_PER_SERVER;
int RA::m_error_log_level = (int) LL_PER_SERVER;
int RA::m_caConns_len = 0;
int RA::m_tksConns_len = 0;
int RA::m_drmConns_len = 0;
int RA::m_auth_len = 0;

#define MAX_BODY_LEN 4096

#define MAX_CA_CONNECTIONS 20
#define MAX_TKS_CONNECTIONS 20
#define MAX_DRM_CONNECTIONS 20
#define MAX_AUTH_LIST_MEMBERS 20
HttpConnection* RA::m_caConnection[MAX_CA_CONNECTIONS];
HttpConnection* RA::m_tksConnection[MAX_TKS_CONNECTIONS];
AuthenticationEntry* RA::m_auth_list[MAX_AUTH_LIST_MEMBERS];
HttpConnection* RA::m_drmConnection[MAX_DRM_CONNECTIONS];
int RA::m_num_publishers = 0;
PublisherEntry *RA::publisher_list = NULL;

/* TKS response parameters */
const char *RA::TKS_RESPONSE_STATUS = "status";
const char *RA::TKS_RESPONSE_SessionKey = "sessionKey";
const char *RA::TKS_RESPONSE_EncSessionKey = "encSessionKey";
const char *RA::TKS_RESPONSE_KEK_DesKey = "kek_wrapped_desKey";
const char *RA::TKS_RESPONSE_DRM_Trans_DesKey = "drm_trans_wrapped_desKey";
const char *RA::TKS_RESPONSE_HostCryptogram = "hostCryptogram";

const char *RA::CFG_DEBUG_ENABLE = "logging.debug.enable"; 
const char *RA::CFG_DEBUG_FILENAME = "logging.debug.filename"; 
const char *RA::CFG_DEBUG_LEVEL = "logging.debug.level";
const char *RA::CFG_AUDIT_ENABLE = "logging.audit.enable"; 
const char *RA::CFG_AUDIT_FILENAME = "logging.audit.filename"; 
const char *RA::CFG_AUDIT_LEVEL = "logging.audit.level";
const char *RA::CFG_ERROR_ENABLE = "logging.error.enable"; 
const char *RA::CFG_ERROR_FILENAME = "logging.error.filename"; 
const char *RA::CFG_ERROR_LEVEL = "logging.error.level";
const char *RA::CFG_CHANNEL_SEC_LEVEL = "channel.securityLevel"; 
const char *RA::CFG_CHANNEL_ENCRYPTION = "channel.encryption";
const char *RA::CFG_APPLET_CARDMGR_INSTANCE_AID = "applet.aid.cardmgr_instance"; 
const char *RA::CFG_APPLET_NETKEY_INSTANCE_AID = "applet.aid.netkey_instance"; 
const char *RA::CFG_APPLET_NETKEY_FILE_AID = "applet.aid.netkey_file"; 
const char *RA::CFG_APPLET_NETKEY_OLD_INSTANCE_AID = "applet.aid.netkey_old_instance"; 
const char *RA::CFG_APPLET_NETKEY_OLD_FILE_AID = "applet.aid.netkey_old_file"; 
const char *RA::CFG_APPLET_SO_PIN = "applet.so_pin"; 
const char *RA::CFG_APPLET_DELETE_NETKEY_OLD = "applet.delete_old"; 

const char *RA::CFG_AUTHS_ENABLE="auth.enable";

/* default values */
const char *RA::CFG_DEF_CARDMGR_INSTANCE_AID = "A0000000030000"; 
const char *RA::CFG_DEF_NETKEY_INSTANCE_AID = "627601FF000000"; 
const char *RA::CFG_DEF_NETKEY_FILE_AID = "627601FF0000"; 
const char *RA::CFG_DEF_NETKEY_OLD_INSTANCE_AID = "A00000000101"; 
const char *RA::CFG_DEF_NETKEY_OLD_FILE_AID = "A000000001"; 
const char *RA::CFG_DEF_APPLET_SO_PIN = "000000000000"; 

typedef IPublisher* (*makepublisher)();
typedef Authentication* (*makeauthentication)();

extern void BuildHostPortLists(char *host, char *port, char **hostList, 
  char **portList, int len);

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Registration Authority object.
 */
RA::RA ()
{ 
}

/**
 * Destructs a Registration Authority object.
 */
RA::~RA ()
{
}

TPS_PUBLIC ConfigStore *RA::GetConfigStore()
{
	return m_cfg;
}

PRLock *RA::GetVerifyLock()
{
  return m_verify_lock;
}

/**
 * Initializes RA with the given configuration file.
 */
TPS_PUBLIC int RA::Initialize(char *cfg_path, RA_Context *ctx)
{
	int rc = -1;
        int i = 0;

    //  Authentication *auth;
	//	int secLevel = 0; // for getting config param
	bool global_enc = false;
	SecurityLevel security_level = SECURE_MSG_MAC_ENC;

	m_verify_lock = PR_NewLock();
	m_debug_log_lock = PR_NewLock();
	m_audit_log_lock = PR_NewLock();
	m_error_log_lock = PR_NewLock();
	m_cfg = ConfigStore::CreateFromConfigFile(cfg_path);
    if( m_cfg == NULL ) {
        rc = -2;
        goto loser;
    }

	if (m_cfg->GetConfigAsBool(CFG_DEBUG_ENABLE, 0)) {
		m_fd_debug = PR_Open(
			m_cfg->GetConfigAsString(CFG_DEBUG_FILENAME, 
				"/tmp/debug.log"), 
			PR_RDWR | PR_CREATE_FILE | PR_APPEND, 
			440 | 220);
		if (m_fd_debug == NULL)
			goto loser;
	}

	if (m_cfg->GetConfigAsBool(CFG_AUDIT_ENABLE, 0)) {
		m_fd_audit = PR_Open(
			m_cfg->GetConfigAsString(CFG_AUDIT_FILENAME, 
				"/tmp/audit.log"), 
			PR_RDWR | PR_CREATE_FILE | PR_APPEND, 
			440 | 220);
		if (m_fd_audit == NULL)
			goto loser;
	}

	if (m_cfg->GetConfigAsBool(CFG_ERROR_ENABLE, 0)) {
		m_fd_error = PR_Open(
			m_cfg->GetConfigAsString(CFG_ERROR_FILENAME, 
				"/tmp/error.log"), 
			PR_RDWR | PR_CREATE_FILE | PR_APPEND, 
			440 | 220);
		if (m_fd_error == NULL)
			goto loser;
	}

        m_audit_log_level = m_cfg->GetConfigAsInt(CFG_AUDIT_LEVEL, (int) LL_PER_SERVER);
        m_debug_log_level = m_cfg->GetConfigAsInt(CFG_DEBUG_LEVEL, (int) LL_PER_SERVER);
        m_error_log_level = m_cfg->GetConfigAsInt(CFG_ERROR_LEVEL, (int) LL_PER_SERVER);

	RA::Debug("RA:: Initialize", "CS TPS starting...");

    rc = InitializeTokendb(cfg_path);
    if( rc != LDAP_SUCCESS ) {
      RA::Debug("RA:: Initialize", "Token DB initialization failed, server continues");
        ctx->LogError( "RA::Initialize",
                       __LINE__,
                       "The TPS plugin could NOT load the "
                       "Tokendb library!  See specific details in the "
                       "TPS plugin log files." );
        // Since the server hasn't started yet, there is
        // no need to perform a call to RA::Shutdown()!
        //goto loser;
    } else
      RA::Debug("RA:: Initialize", "Token DB initialization succeeded");

    //testTokendb();

    m_pod_enable = m_cfg->GetConfigAsBool("failover.pod.enable", false);
    m_pod_curr = 0;
    m_auth_curr = 0;
    m_pod_lock = PR_NewLock();
    m_auth_lock = PR_NewLock();


    // make encryption not default for operations globally
    // individual security levels can override
    //    secLevel = RA::GetConfigAsInt(RA::CFG_CHANNEL_SEC_LEVEL,
    //				  SECURE_MSG_MAC);

    global_enc = m_cfg->GetConfigAsBool(RA::CFG_CHANNEL_ENCRYPTION, true);
    if (global_enc == true)
	  security_level = SECURE_MSG_MAC_ENC;
	else
	  security_level = SECURE_MSG_MAC;

    RA::SetGlobalSecurityLevel(security_level);

    // Initialize the CA connection pool to be empty
    for (i=0; i<MAX_CA_CONNECTIONS; i++) {
        m_caConnection[i] = NULL;
    }

    // Initialize the TKS connection pool to be empty
    for (i=0; i<MAX_TKS_CONNECTIONS; i++) {
        m_tksConnection[i] = NULL;
    }

    // Initialize the DRM connection pool to be empty
    for (i=0; i<MAX_DRM_CONNECTIONS; i++) {
        m_drmConnection[i] = NULL;
    }

    // Initialize the authentication list to be empty
    for (i=0; i<MAX_AUTH_LIST_MEMBERS; i++) {
        m_auth_list[i] = NULL;
    }

    // even rc != 0, we still go ahead starting up the server.
    rc = InitializeAuthentication();

    //Initialize Publisher Library
      InitializePublishers();

	rc = 1;
loser:
	
    // Log the status of this TPS plugin into the web server's log:
    if( rc != 1 ) {
        ctx->LogError( "RA::Initialize",
                       __LINE__,
                       "The TPS plugin could NOT be "
                       "loaded (rc = %d)!  See specific details in the "
                       "TPS plugin log files.", rc );
    } else {
        ctx->LogInfo( "RA::Initialize",
                      __LINE__,
                      "The TPS plugin was "
                      "successfully loaded!" );
    }

	return rc;
}

int RA::InitializeInChild(RA_Context *ctx) {

    int rc = -1;
    SECStatus rv;
    int status = 0;
    char configname[256];

    if (!NSS_IsInitialized()) {

        RA::Debug( LL_PER_SERVER, "RA::InitializeInChild", "Initializing NSS");

        PR_snprintf((char *)configname, 256, "%s/alias", 
            m_cfg->GetConfigAsString("service.instanceDir", NULL));
        rv = NSS_Initialize (configname, "", "", SECMOD_DB, NSS_INIT_READONLY);
        if (rv != SECSuccess) {
            RA::Error( LL_PER_SERVER, "RA::InitializeInChild",
                "NSS not initialized successfully");
            ctx->InitializationError( "RA::InitializeHttpConnections",
                                       __LINE__ );
            goto loser;
        }
    }

    //initialize CA Connections
    status = InitializeHttpConnections("ca", &m_caConns_len,
         m_caConnection, ctx);
    if (status != 0) {
        RA::Debug( LL_PER_SERVER, "RA::InitializeInChild", 
            "Failed to initialize CA Connection, rc=%i", 
            (int)status);
    } 
    // initialize TKS connections
    status = InitializeHttpConnections("tks", &m_tksConns_len,
        m_tksConnection, ctx);
    if (status != 0) {
        RA::Debug( LL_PER_SERVER, "RA::InitializeInChild", 
            "Failed to initialize TKS Connection, rc=%i", 
            (int)status);
    } 
    // initialize DRM connections
    status = InitializeHttpConnections("drm", &m_drmConns_len,
        m_drmConnection, ctx);
    if (status != 0) {
        RA::Debug( LL_PER_SERVER, "RA::InitializeInChild", 
            "Failed to initialize DRM Connection, rc=%i", 
            (int)status);
    } 

    rc =1;
loser: 
    return rc;
}

int RA::testTokendb() {
	// try to see if we can talk to the database
	int st = 0;
	LDAPMessage  *ldapResult = NULL;
	const char * filter = "(cn=0000000000080000*)";

	if ((st = find_tus_db_entries(filter, 0, &ldapResult)) != LDAP_SUCCESS) {
	  RA::Debug("RA::testing", "response from token DB failed");
	} else {
	  RA::Debug("RA::testing", "response from token DB succeeded");
	}

	return st;
}

int RA::IsTokendbInitialized()
{
  return tokendbInitialized;
}


/**
 * Shutdown RA.
 */
TPS_PUBLIC int RA::Shutdown()
{

    tus_db_end();

    if( m_pod_lock != NULL ) {
        PR_DestroyLock( m_pod_lock );
        m_pod_lock = NULL;
    }

    if( m_auth_lock != NULL ) {
        PR_DestroyLock( m_auth_lock );
        m_auth_lock = NULL;
    }

    if (m_caConnection != NULL) {
        for (int i=0; i<m_caConns_len; i++) {
            if( m_caConnection[i] != NULL ) {
                delete m_caConnection[i];
                m_caConnection[i] = NULL;
            }
        }
    }

    if (m_tksConnection != NULL) {
        for (int i=0; i<m_tksConns_len; i++) {
            if( m_tksConnection[i] != NULL ) {
                delete m_tksConnection[i];
                m_tksConnection[i] = NULL;
            }
        }
    }
    if (m_drmConnection != NULL) {
        for (int i=0; i<m_drmConns_len; i++) {
            if( m_drmConnection[i] != NULL ) {
                delete m_drmConnection[i];
                m_drmConnection[i] = NULL;
            }
        }
    }

	/* close debug file if opened */
	if( m_fd_debug != NULL ) {
	    PR_Close( m_fd_debug );
        m_fd_debug = NULL;
    }

	/* close audit file if opened */
	if( m_fd_audit != NULL ) {
	    PR_Close( m_fd_audit );
        m_fd_audit = NULL;
    }

	/* close error file if opened */
	if( m_fd_error != NULL ) {
	    PR_Close( m_fd_error );
        m_fd_error = NULL;
    }

    if( m_verify_lock != NULL ) {
        PR_DestroyLock( m_verify_lock );
        m_verify_lock = NULL;
    }

    if( m_debug_log_lock != NULL ) {
        PR_DestroyLock( m_debug_log_lock );
        m_debug_log_lock = NULL;
    }

    if( m_audit_log_lock != NULL ) {
        PR_DestroyLock( m_audit_log_lock );
        m_audit_log_lock = NULL;
    }

    if( m_error_log_lock != NULL ) {
        PR_DestroyLock( m_error_log_lock );
        m_error_log_lock = NULL;
    }

    if (m_auth_list != NULL) {
        for (int i=0; i<m_auth_len; i++) {
            if( m_auth_list[i] != NULL ) {
                delete m_auth_list[i];
                m_auth_list[i] = NULL;
            }
        }
    }

    /* destroy configuration hashtable */
    if( m_cfg != NULL ) {
        delete m_cfg;
        m_cfg = NULL;
    }

    CleanupPublishers();

    return 1;
}

HttpConnection *RA::GetTKSConn(const char *id) {
    HttpConnection *tksconn = NULL;
    for (int i=0; i<m_tksConns_len; i++) {
        if (strcmp(m_tksConnection[i]->GetId(), id) == 0) {
            tksconn = m_tksConnection[i];   
            break;
        }
    }
    return tksconn; 
}

HttpConnection *RA::GetDRMConn(const char *id) {
    HttpConnection *drmconn = NULL;
    for (int i=0; i<m_drmConns_len; i++) {
        if (strcmp(m_drmConnection[i]->GetId(), id) == 0) {
            drmconn = m_drmConnection[i];   
            break;
        }
    }
    return drmconn; 
}

void RA::ReturnTKSConn(HttpConnection *conn) {
    // do nothing for now
}

void RA::ReturnDRMConn(HttpConnection *conn) {
    // do nothing for now
}

HttpConnection *RA::GetCAConn(const char *id) {
    HttpConnection *caconn = NULL;
    if (id == NULL)
      return NULL;
    for (int i=0; i<m_caConns_len; i++) {
        if (strcmp(m_caConnection[i]->GetId(), id) == 0) {
            caconn = m_caConnection[i];
            break;
        }
    }
    return caconn;
}

AuthenticationEntry *RA::GetAuth(const char *id) {
    AuthenticationEntry *authEntry = NULL;
    for (int i=0; i<m_auth_len; i++) {
        authEntry = m_auth_list[i];
        if (strcmp(authEntry->GetId(), id) == 0)
            return authEntry;
    }
    return NULL;
}

void RA::ReturnCAConn(HttpConnection *conn) {
    // do nothing for now
}

TPS_PUBLIC PRLock *RA::GetAuthLock() {
    return m_auth_lock;
}

int RA::GetPodIndex() {
    PR_Lock(m_pod_lock);
    int index = m_pod_curr;
    PR_Unlock(m_pod_lock);
    return index;
}

void RA::SetPodIndex(int index) {
    PR_Lock(m_pod_lock);
    m_pod_curr = index;
    PR_Unlock(m_pod_lock);
}

void RA::SetCurrentIndex(HttpConnection *&conn, int index) {
    PRLock *lock = conn->GetLock();
    PR_Lock(lock);
    conn->SetCurrentIndex(index);
    PR_Unlock(lock);
}

int RA::GetCurrentIndex(HttpConnection *conn) {
    PRLock *lock = conn->GetLock();
    PR_Lock(lock);
    int index = conn->GetCurrentIndex();
    PR_Unlock(lock);
    return index;
}

TPS_PUBLIC int RA::GetAuthCurrentIndex() {
    PR_Lock(m_auth_lock);
    int index = m_auth_curr;
    PR_Unlock(m_auth_lock);
    return index;
}

void RA::SetAuthCurrentIndex(int index) {
    PR_Lock(m_auth_lock);
    m_auth_curr = index;
    PR_Unlock(m_auth_lock);
}

TPS_PUBLIC void RA::IncrementAuthCurrentIndex(int len) {
    PR_Lock(m_auth_lock);
    if ((++m_auth_curr) >= len)
        m_auth_curr = 0;
    PR_Unlock(m_auth_lock);
}

void RA::SetGlobalSecurityLevel(SecurityLevel sl) {
    m_global_security_level = sl;
    RA::Debug(" RA::SetGlobalSecurityLevel", "global security level set to %d", (int) sl);

}

SecurityLevel RA::GetGlobalSecurityLevel() {
    return m_global_security_level;
}


/*
 * recovers user encryption key that was previously archived.
 * It expects DRM to search its archival db by cert.
 *
 * input:
 * @param cuid (cuid of the recovering key's token)
 * @param userid (uid of the recovering key owner
 * @param desKey_s (came from TKS - session key wrapped with DRM transport
 * @param cert (base64 encoded cert of the recovering key)
 * @param connId (drm connectoin id)
 *
 * output:
 * @param publickey_s public key provided by DRM
 * @param wrappedPrivateKey_s encrypted private key provided by DRM
 */
void RA::RecoverKey(RA_Session *session, const char* cuid,
                    const char *userid, char* desKey_s,
                    char *b64cert, char **publicKey_s,
                    char **wrappedPrivateKey_s, const char *connId)
{
    int status;
    PSHttpResponse *response = NULL;
    HttpConnection *drmConn = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];
    char * cert_s;
    int drm_curr = 0;
    long s;
    char * content = NULL;
    char ** hostport= NULL;
    const char* servletID = NULL;
    char *wrappedDESKey_s= NULL;
    Buffer *decodeKey = NULL;
    ConnectionInfo *connInfo = NULL;
    RA_pblock *ra_pb = NULL;
    int currRetries = 0;
    char *p = NULL;

    RA::Debug(" RA:: RecoverKey", "in RecoverKey");
    if (cuid == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, cuid NULL");
      goto loser;
    }
    if (userid == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, userid NULL");
      goto loser;
    }
    if (b64cert == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, b64cert NULL");
      goto loser;
    }
    if (desKey_s == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, desKey_s NULL");
      goto loser;
    }
    if (connId == NULL) {
      RA::Debug(" RA:: RecoverKey", "in RecoverKey, connId NULL");
      goto loser;
    }
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, desKey_s=%s, connId=%s",desKey_s,  connId);

    cert_s = Util::URLEncode(b64cert);
    drmConn = RA::GetDRMConn(connId);
    if (drmConn == NULL) {
        RA::Debug(" RA:: RecoverKey", "in RecoverKey, failed getting drmconn");
	goto loser;
    }
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, got drmconn");
    connInfo = drmConn->GetFailoverList();
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, got drm failover");
    decodeKey = Util::URLDecode(desKey_s);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey,url decoded des");
    wrappedDESKey_s = Util::SpecialURLEncode(*decodeKey);

    RA::Debug(" RA:: RecoverKey", "in RecoverKey, wrappedDESKey_s=%s", wrappedDESKey_s);

    PR_snprintf((char *)body, MAX_BODY_LEN, 
		"CUID=%s&userid=%s&drm_trans_desKey=%s&cert=%s",cuid, userid, wrappedDESKey_s, cert_s);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, body=%s", body);
        PR_snprintf((char *)configname, 256, "conn.%s.servlet.TokenKeyRecovery", connId);
        servletID = GetConfigStore()->GetConfigAsString(configname);
    RA::Debug(" RA:: RecoverKey", "in RecoverKey, configname=%s", configname);

    drm_curr = RA::GetCurrentIndex(drmConn);
    response = drmConn->getResponse(drm_curr, servletID, body);
    hostport = connInfo->GetHostPortList();
    if (response == NULL) {
        RA::Debug(LL_PER_PDU, "The recoverKey response from DRM ", 
          "at %s is NULL.", hostport[drm_curr]);
 
      //goto loser;
    } else {
        RA::Debug(LL_PER_PDU, "The recoverKey response from DRM ", 
          "at %s is not NULL.", hostport[drm_curr]);
    }

    while (response == NULL) {
        RA::Failover(drmConn, connInfo->GetHostPortListLen());
    
        drm_curr = RA::GetCurrentIndex(drmConn);
        RA::Debug(LL_PER_PDU, "RA is reconnecting to DRM ", 
          "at %s for recoverKey.", hostport[drm_curr]);
    
        if (++currRetries >= drmConn->GetNumOfRetries()) {
            RA::Debug("Used up all the retries in recoverKey. Response is NULL","");
            RA::Error("RA::RecoverKey","Failed connecting to DRM after %d retries", currRetries);

            goto loser;
        }
        response = drmConn->getResponse(drm_curr, servletID, body);
    }

    RA::Debug(" RA:: RecoverKey", "in RecoverKey - got response");
    // XXXskip handling fallback host for prototype

    content = response->getContent();
    p = strstr(content, "status=");
    content = p; //skip the HTTP header

    s = response->getStatus();

    if ((content != NULL) && (s == 200)) {
      RA::Debug("RA::RecoverKey", "response from DRM status ok");

      Buffer* status_b;
      char* status_s;

      ra_pb = ( RA_pblock * ) session->create_pblock(content);
      if (ra_pb == NULL)
	goto loser;

      status_b = ra_pb->find_val("status");
      if (status_b == NULL) {
	status = 4;
	goto loser;
      }
      else {
	status_s = status_b->string();
	status = atoi(status_s);
      }


      char * tmp = NULL;
      tmp = ra_pb->find_val_s("public_key");
      if ((tmp == NULL) || (tmp == "")) {
	RA::Error(LL_PER_PDU, "RecoverKey"," got no public key");
	goto loser;
      } else {
	RA::Debug(LL_PER_PDU, "RecoverKey", "got public key =%s", tmp);
	*publicKey_s  = PL_strdup(tmp);
      }

      tmp = NULL;
      tmp = ra_pb->find_val_s("wrapped_priv_key");
      if ((tmp == NULL) || (tmp == "")) {
	RA::Error(LL_PER_PDU, "RecoverKey"," got no wrapped private key");
	//XXX	      goto loser;
      } else {
	RA::Debug(LL_PER_PDU, "RecoverKey", "got wrappedprivate key =%s", tmp);
	*wrappedPrivateKey_s  = PL_strdup(tmp);
      }

    } else {// if content is NULL or status not 200
      if (content != NULL)
	RA::Debug("RA::RecoverKey", "response from DRM error status %ld", s);
      else
	RA::Debug("RA::RecoverKey", "response from DRM no content");
    }
 loser:
    if (desKey_s != NULL)
      PR_Free(desKey_s);

    if (decodeKey != NULL)
      PR_Free(decodeKey);

    if (wrappedDESKey_s != NULL)
      PR_Free(wrappedDESKey_s);

    if (drmConn != NULL)
      RA::ReturnDRMConn(drmConn);

    if (response != NULL) {
      if (content != NULL)
	response->freeContent();
      delete response;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }

}



/*
 * input:
 * @param desKey_s provided for drm to wrap user private
 * @param publicKey_s returned for key injection back to token
 *
 * Output:
 * @param publicKey_s public key provided by DRM
 * @param wrappedPrivateKey_s encrypted private key provided by DRM
 */
void RA::ServerSideKeyGen(RA_Session *session, const char* cuid,
                          const char *userid, char* desKey_s,
	                      char **publicKey_s,
                          char **wrappedPrivateKey_s,
                          char **ivParam_s, const char *connId,
                          bool archive, int keysize)
{

	const char *FN="RA::ServerSideKeyGen";
    int status;
    PSHttpResponse *response = NULL;
    HttpConnection *drmConn = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];

    long s;
    char * content = NULL;
    char ** hostport = NULL;
    const char* servletID = NULL;
    char *wrappedDESKey_s = NULL;
    Buffer *decodeKey = NULL;
    ConnectionInfo *connInfo = NULL;
    RA_pblock *ra_pb = NULL;
    int drm_curr = 0;
    int currRetries = 0;
    char *p = NULL;

    if ((cuid == NULL) || (cuid == "")) {
      RA::Debug( LL_PER_CONNECTION, FN,
			"error: passed invalid cuid");
      goto loser;
    }
    if ((userid == NULL) || (userid =="")) {
      RA::Debug(LL_PER_CONNECTION, FN,
			"error: passed invalid userid");
      goto loser;
    }
    if ((desKey_s == NULL) || (desKey_s =="")) {
      RA::Debug(LL_PER_CONNECTION, FN, 
			 "error: passed invalid desKey_s");
      goto loser;
    }
    if ((connId == NULL) ||(connId == "")) {
      RA::Debug(LL_PER_CONNECTION, FN,
			 "error: passed invalid connId");
      goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
			 "desKey_s=%s, connId=%s",desKey_s,  connId);
    drmConn = RA::GetDRMConn(connId);

    if (drmConn == NULL) {
        RA::Debug(LL_PER_CONNECTION, FN,
			"drmconn is null");
		goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
			"found DRM connection info");
    connInfo = drmConn->GetFailoverList();
    RA::Debug(LL_PER_CONNECTION, FN,
		 "got DRM failover list");

    decodeKey = Util::URLDecode(desKey_s);
    if (decodeKey == NULL) {
      RA::Debug(LL_PER_CONNECTION, FN,
		"url-decoding of des key-transport-key failed");
      goto loser;
    }
    RA::Debug(LL_PER_CONNECTION, FN,
		"successfully url-decoded key-transport-key");
    wrappedDESKey_s = Util::SpecialURLEncode(*decodeKey);

    RA::Debug(LL_PER_CONNECTION, FN,
		"wrappedDESKey_s=%s", wrappedDESKey_s);

    PR_snprintf((char *)body, MAX_BODY_LEN, 
		"archive=%s&CUID=%s&userid=%s&keysize=%d&drm_trans_desKey=%s",archive?"true":"false",cuid, userid, keysize, wrappedDESKey_s);
    RA::Debug(LL_PER_CONNECTION, FN, 
		"sending to DRM: query=%s", body);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.GenerateKeyPair", connId);
    servletID = GetConfigStore()->GetConfigAsString(configname);
    RA::Debug(LL_PER_CONNECTION, FN,
		 "finding DRM servlet info, configname=%s", configname);

    drm_curr = RA::GetCurrentIndex(drmConn);
    response = drmConn->getResponse(drm_curr, servletID, body);
    hostport = connInfo->GetHostPortList();
    if (response == NULL) {
        RA::Error(LL_PER_CONNECTION, FN, 
			"failed to get response from DRM at %s", 
			hostport[drm_curr]);
        RA::Debug(LL_PER_CONNECTION, FN, 
			"failed to get response from DRM at %s", 
			hostport[drm_curr]);
    } else { 
        RA::Debug(LL_PER_CONNECTION, FN,
			"response from DRM (%s) is not NULL.",
			 hostport[drm_curr]);
    }

    while (response == NULL) {
        RA::Failover(drmConn, connInfo->GetHostPortListLen());

        drm_curr = RA::GetCurrentIndex(drmConn);
        RA::Debug(LL_PER_CONNECTION, FN,
			"RA is failing over to DRM at %s", hostport[drm_curr]);

        if (++currRetries >= drmConn->GetNumOfRetries()) {
            RA::Debug(LL_PER_CONNECTION, FN,
				"Failed to get response from all DRMs in conn group '%s'"
				" after %d retries", connId, currRetries);
            RA::Error(LL_PER_CONNECTION, FN,
				"Failed to get response from all DRMs in conn group '%s'"
				" after %d retries", connId, currRetries);


            goto loser;
        }
        response = drmConn->getResponse(drm_curr, servletID, body);
    }

    RA::Debug(" RA:: ServerSideKeyGen", "in ServerSideKeyGen - got response");
    // XXX skip handling fallback host for prototype

    content = response->getContent();
    p = strstr(content, "status=");
    content = p; //skip the HTTP header
    s = response->getStatus();

    if ((content != NULL) && (s == 200)) {
	  RA::Debug("RA::ServerSideKeyGen", "response from DRM status ok");

	  Buffer* status_b;
	  char* status_s;

	  ra_pb = ( RA_pblock * ) session->create_pblock(content);
	  if (ra_pb == NULL)
	    goto loser;

	  status_b = ra_pb->find_val("status");
	  if (status_b == NULL) {
	    status = 4;
	    goto loser;
	  } else {
	    status_s = status_b->string();
	    status = atoi(status_s);
	  }

	  char * tmp = NULL;
	  tmp = ra_pb->find_val_s("public_key");
	  if (tmp == NULL) {
	    RA::Error(LL_PER_CONNECTION, FN,
			"Did not get public key in DRM response");
	  } else {
	    RA::Debug(LL_PER_PDU, "ServerSideKeyGen", "got public key =%s", tmp);
	    *publicKey_s  = PL_strdup(tmp);
	  }

	  tmp = NULL;
	  tmp = ra_pb->find_val_s("wrapped_priv_key");
	  if ((tmp == NULL) || (tmp == "")) {
	    RA::Error(LL_PER_CONNECTION, FN,
				"did not get wrapped private key in DRM response");
	  } else {
	    RA::Debug(LL_PER_CONNECTION, FN,
			"got wrappedprivate key =%s", tmp);
	    *wrappedPrivateKey_s  = PL_strdup(tmp);
	  }

	  tmp = ra_pb->find_val_s("iv_param");
	  if ((tmp == NULL) || (tmp == "")) {
	    RA::Error(LL_PER_CONNECTION, FN,
				"did not get iv_param for private key in DRM response");
	  } else {
	    RA::Debug(LL_PER_PDU, "ServerSideKeyGen", "got iv_param for private key =%s", tmp);
	    *ivParam_s  = PL_strdup(tmp);
	  }

    } else {// if content is NULL or status not 200
	  if (content != NULL)
	    RA::Debug("RA::ServerSideKeyGen", "response from DRM error status %ld", s);
	  else
	    RA::Debug("RA::ServerSideKeyGen", "response from DRM no content");
    }

 loser:
    if (desKey_s != NULL)
      PR_Free(desKey_s);

    if (decodeKey != NULL) {
      delete decodeKey;
    }

    if (wrappedDESKey_s != NULL)
      PR_Free(wrappedDESKey_s);

    if (drmConn != NULL)
      RA::ReturnDRMConn(drmConn);

    if (response != NULL) {
      if (content != NULL)
	response->freeContent();
      delete response;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }

}


#define DES2_WORKAROUND
#define MAX_BODY_LEN 4096

PK11SymKey *RA::ComputeSessionKey(RA_Session *session,
                                  Buffer &CUID,
                                  Buffer &keyInfo,
                                  Buffer &card_challenge,
                                  Buffer &host_challenge,
                                  Buffer **host_cryptogram,
                                  Buffer &card_cryptogram,
                                  PK11SymKey **encSymKey,
                                  char** drm_desKey_s,
                                  char** kek_desKey_s,
                                  char** keycheck_s,
                                  const char *connId)
{
    PK11SymKey *symKey = NULL;
    char body[MAX_BODY_LEN];
    char configname[256];
    char * cardc = NULL;
    char * hostc = NULL;
    char * cardCrypto = NULL;
    char * cuid = NULL;
    char * keyinfo =  NULL;
    PSHttpResponse *response = NULL;
    HttpConnection *tksConn = NULL;
    RA_pblock *ra_pb = NULL;

    RA::Debug(LL_PER_PDU, "Start ComputeSessionKey", "");
    tksConn = RA::GetTKSConn(connId);
    if (tksConn == NULL) {
        RA::Error(LL_PER_PDU, "RA::ComputeSessionKey", "Failed to get TKSConnection %s", connId);
        return NULL;
    } else {
        int currRetries = 0;
        ConnectionInfo *connInfo = tksConn->GetFailoverList();

	PR_snprintf((char *) configname, 256, "conn.%s.keySet", connId);
	const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname, "defKeySet");
	// is serversideKeygen on?
	PR_snprintf((char *) configname, 256, "conn.%s.serverKeygen", connId);
	bool serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, false);
	if (serverKeygen)
	  RA::Debug(LL_PER_PDU, "RA::ComputeSessionKey", "serverKeygen for %s is on", connId);
	else
	  RA::Debug(LL_PER_PDU, "RA::ComputeSessionKey", "serverKeygen for %s is off", connId);

        cardc = Util::SpecialURLEncode(card_challenge);
        hostc = Util::SpecialURLEncode(host_challenge);
        cardCrypto = Util::SpecialURLEncode(card_cryptogram);
        cuid = Util::SpecialURLEncode(CUID);
        keyinfo = Util::SpecialURLEncode(keyInfo);

        if ((cardc == NULL) || (hostc == NULL) || (cardCrypto == NULL) ||
          (cuid == NULL) || (keyinfo == NULL))
	    goto loser;

        PR_snprintf((char *)body, MAX_BODY_LEN, 
          "serversideKeygen=%s&CUID=%s&card_challenge=%s&host_challenge=%s&KeyInfo=%s&card_cryptogram=%s&keySet=%s", serverKeygen? "true":"false", cuid, 
          cardc, hostc, keyinfo, cardCrypto, keySet);

        PR_snprintf((char *)configname, 256, "conn.%s.servlet.computeSessionKey", connId);
        const char *servletID = GetConfigStore()->GetConfigAsString(configname);
        int tks_curr = RA::GetCurrentIndex(tksConn);
        response = tksConn->getResponse(tks_curr, servletID, body);
        char **hostport = connInfo->GetHostPortList();
        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The computeSessionKey response from TKS ", 
              "at %s is NULL.", hostport[tks_curr]);
        else 
            RA::Debug(LL_PER_PDU, "The computeSessionKey response from TKS ", 
              "at %s is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());

            tks_curr = RA::GetCurrentIndex(tksConn);
            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ", 
              "at %s for computeSessionKey.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug("Used up all the retries in ComputeSessionKey. Response is NULL","");
                RA::Error("RA::ComputeSessionKey","Failed connecting to TKS after %d retries", currRetries);

                goto loser;
            }
            response = tksConn->getResponse(tks_curr, servletID, body); 
        }

        RA::Debug(LL_PER_PDU, "ComputeSessionKey Response is not ","NULL");
        char * content = response->getContent();

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

        if (content != NULL) {
	  Buffer *status_b;

	  char *status_s, *sessionKey_s, *encSessionKey_s, *hostCryptogram_s;
	  int status;

      /* strip the http header */
      /* raidzilla 57722: strip the HTTP header and just pass
         name value pairs into the pblock parsing code.
       */
      RA::Debug("RA::Engine", "Pre-processing content '%s", content);
      char *cx = content;
      while (cx[0] != '\0' && (!(cx[0] == '\r' && cx[1] == '\n' && 
                 cx[2] == '\r' && cx[3] == '\n')))
      {
          cx++;
      }
      if (cx[0] != '\0') {
          cx+=4;
      }
      RA::Debug("RA::Engine", "Post-processing content '%s", cx);
	  ra_pb = ( RA_pblock * ) session->create_pblock(cx);
	  if (ra_pb == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no ra_pb");
	    goto loser;
	  }

	status_b = ra_pb->find_val(TKS_RESPONSE_STATUS);
	if (status_b == NULL) {
	  status = 4;
	    RA::Error(LL_PER_SERVER, "RA:ComputeSessionKey", "Bad TKS Connection. Please make sure TKS is accessible by TPS.");
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no status");
      goto loser;
	  // return NULL;
	}
	else {
	  status_s = status_b->string();
	  status = atoi(status_s);
	}

	sessionKey_s = ra_pb->find_val_s(TKS_RESPONSE_SessionKey);
	if (sessionKey_s == NULL) {
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no sessionKey_b");
	  goto loser;
	}

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "mac session key=%s", sessionKey_s);
	Buffer *decodeKey = Util::URLDecode(sessionKey_s);

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "decodekey len=%d",decodeKey->size());

	BYTE masterKeyData[24];
	SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData)};
	BYTE *keyData = (BYTE *)*decodeKey;
	memcpy(masterKeyData, (char*)keyData, 16);
	memcpy(masterKeyData+16, (char*)keyData, 8);

	symKey = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
					    PK11_OriginGenerated, CKA_ENCRYPT, &masterKeyItem,
					    CKF_ENCRYPT, PR_FALSE, 0);

	if( decodeKey != NULL ) {
	  delete decodeKey;
	  decodeKey = NULL;
	}
	if (symKey == NULL)
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "MAC Session key is NULL");


	encSessionKey_s = ra_pb->find_val_s(TKS_RESPONSE_EncSessionKey);
	if (encSessionKey_s == NULL) {
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "fail no encSessionKey_b");
	  goto loser;
	}

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "encSessionKey=%s", encSessionKey_s);
	Buffer *decodeEncKey = Util::URLDecode(encSessionKey_s);

	RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey",
		  "decodeEnckey len=%d",decodeEncKey->size());

	BYTE masterEncKeyData[24];
	SECItem masterEncKeyItem =
	  {siBuffer, masterEncKeyData, sizeof(masterEncKeyData)};
	BYTE *EnckeyData = (BYTE *)*decodeEncKey;
	memcpy(masterEncKeyData, (char*)EnckeyData, 16);
	memcpy(masterEncKeyData+16, (char*)EnckeyData, 8);

	*encSymKey =
	  PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
				     PK11_OriginGenerated, CKA_ENCRYPT, &masterEncKeyItem,
				     CKF_ENCRYPT, PR_FALSE, 0);

	if( decodeEncKey != NULL ) {
	  delete decodeEncKey;
	  decodeEncKey = NULL;
	}

	if (encSymKey == NULL)
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "encSessionKey is NULL");


	if (serverKeygen) {
	  char * tmp= NULL;
	  tmp = ra_pb->find_val_s(TKS_RESPONSE_DRM_Trans_DesKey);
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey not retrieved");
	    goto loser;
	  } else {
	    *drm_desKey_s = PL_strdup(tmp);
	  }
	  // wrapped des key is to be sent to DRM "as is"
	  // thus should not be touched
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "drm_desKey=%s", *drm_desKey_s );

	  tmp = ra_pb->find_val_s(TKS_RESPONSE_KEK_DesKey);
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "kek-wrapped desKey not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "kek-wrapped desKey not retrieved");
	    goto loser;
	  } else {
	    *kek_desKey_s = PL_strdup(tmp);
	  }
	  RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "kek_desKey=%s", *kek_desKey_s );


	  tmp = ra_pb->find_val_s("keycheck");
	  if (tmp == NULL) {
	    RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "keycheck not retrieved");
	    RA::Error(LL_PER_PDU, "RA:ComputeSessionKey", "keycheck not retrieved");
	    goto loser;
	  } else {
	    *keycheck_s = PL_strdup(tmp);
	  }
	}// serversideKeygen

	hostCryptogram_s = ra_pb->find_val_s(TKS_RESPONSE_HostCryptogram);
	if (hostCryptogram_s == NULL)
	  goto loser;

                        RA::Debug(LL_PER_PDU, "RA:ComputeSessionKey", "hostC=%s", hostCryptogram_s);
                        *host_cryptogram = Util::URLDecode(hostCryptogram_s);
	} // if content != NULL

    } // else tksConn != NULL
        RA::Debug(LL_PER_PDU, "finish ComputeSessionKey", "");


 loser:
	if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	}
    if( cardc != NULL ) {
        PR_Free( cardc );
        cardc = NULL;
    }
    if( hostc != NULL ) {
        PR_Free( hostc );
        hostc = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( cuid );
        cuid = NULL;
    }
    if( keyinfo != NULL ) {
        PR_Free( keyinfo );
        keyinfo = NULL;
    }
    if (cardCrypto != NULL) {
        PR_Free( cardCrypto );
        cardCrypto = NULL;
    }

    if( response != NULL ) {
        response->freeContent();
        delete response;
        response = NULL;
    }

    if (ra_pb != NULL) {
      delete ra_pb;
    }
	// in production, if TKS is unreachable, symKey will be NULL,
	// and this will signal error to the caller.
	return symKey;

}

Buffer *RA::ComputeHostCryptogram(Buffer &card_challenge, 
		Buffer &host_challenge)
{ 
	/* hardcoded enc auth key */
	BYTE enc_auth_key[16] = {
		0x40, 0x41, 0x42, 0x43, 
		0x44, 0x45, 0x46, 0x47, 
		0x48, 0x49, 0x4a, 0x4b, 
		0x4c, 0x4d, 0x4e, 0x4f 
	};
	Buffer input = Buffer(16, (BYTE)0);
	int i;
	Buffer icv = Buffer(8, (BYTE)0);
	Buffer *output = new Buffer(8, (BYTE)0);
	BYTE *cc = (BYTE*)card_challenge;
	int cc_len = card_challenge.size();
	BYTE *hc = (BYTE*)host_challenge;
	int hc_len = host_challenge.size();

	/* copy card and host challenge into input buffer */
	for (i = 0; i < 8; i++) {
		((BYTE*)input)[i] = cc[i];
	}
	for (i = 0; i < 8; i++) {
		((BYTE*)input)[8+i] = hc[i];
	}

	PK11SymKey *key = Util::DeriveKey(
		Buffer(enc_auth_key, 16), Buffer(hc, hc_len), 
		Buffer(cc, cc_len));
	Util::ComputeMAC(key, input, icv, *output);

	return output;
}

TPS_PUBLIC void RA::DebugBuffer(const char *func_name, const char *prefix, Buffer *buf)
{
	RA::DebugBuffer(LL_PER_CONNECTION, func_name, prefix, buf);
}

void RA::DebugBuffer(RA_Log_Level level, const char *func_name, const char *prefix, Buffer *buf)
{
    int i;
    PRTime now;
    const char* time_fmt = "%Y-%m-%d %H:%M:%S";
    char datetime[1024]; 
    PRExplodedTime time;
    BYTE *data = *buf;
    int sum = 0;
	PRThread *ct;

    if (m_fd_debug == NULL) 
		return;
    if ((int) level >= m_debug_log_level)
		return;
    PR_Lock(m_debug_log_lock);
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    ct = PR_GetCurrentThread();
    PR_fprintf(m_fd_debug, "[%s] %x %s - ", datetime, ct, func_name);
    PR_fprintf(m_fd_debug, "%s (length='%d')", prefix, buf->size());
    PR_fprintf(m_fd_debug, "\n");
    PR_fprintf(m_fd_debug, "[%s] %x %s - ", datetime, ct, func_name);
    for (i=0; i<(int)buf->size(); i++) {
        PR_fprintf(m_fd_debug, "%02x ", (unsigned char)data[i]);
        sum++; 
	if (sum == 10) {
    		PR_fprintf(m_fd_debug, "\n");
                PR_fprintf(m_fd_debug, "[%s] %x %s - ", datetime, ct, func_name);
                sum = 0;
	}
    }
    PR_Write(m_fd_debug, "\n", 1);
    PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Debug (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Debug (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::DebugThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if (m_fd_debug == NULL) 
		return;
	if ((int) level >= m_debug_log_level)
		return;
	PR_Lock(m_debug_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	PR_fprintf(m_fd_debug, "[%s] %x %s - ", datetime, ct, func_name);
	PR_vfprintf(m_fd_debug, fmt, ap); 
	PR_Write(m_fd_debug, "\n", 1);
	PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Audit (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::AuditThis (LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis (LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Audit (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::AuditThis (level, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis (level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::AuditThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if (m_fd_audit == NULL) 
		return;
	if ((int) level >= m_audit_log_level)
		return;
	PR_Lock(m_audit_log_lock);
	now = PR_Now();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	ct = PR_GetCurrentThread();
	PR_fprintf(m_fd_audit, "[%s] %x %s - ", datetime, ct, func_name);
	PR_vfprintf(m_fd_audit, fmt, ap); 
	PR_Write(m_fd_audit, "\n", 1);
	PR_Unlock(m_audit_log_lock);
}

TPS_PUBLIC void RA::Error (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Error (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(level, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::ErrorThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if (m_fd_error == NULL) 
		return;
	if ((int) level >= m_error_log_level)
		return;
	PR_Lock(m_error_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	PR_fprintf(m_fd_error, "[%s] %x %s - ", datetime, ct, func_name);
	PR_vfprintf(m_fd_error, fmt, ap); 
	PR_Write(m_fd_error, "\n", 1);
	PR_Unlock(m_error_log_lock);
}

PublisherEntry *RA::getPublisherById(const char *publisher_id)
{

    PublisherEntry *cur = RA::publisher_list;

    if(cur == NULL)
    {
         return NULL;
    }

    while(cur != NULL)
    {
       if(!strcmp(publisher_id,cur->id))
       {
           break;
       }

       cur = cur->next;
    }

    return cur;

}

int RA::InitializePublishers()

{
    RA::m_num_publishers = 0;

    RA::Debug(LL_PER_PDU, "RA::InitializePublishers: Attempting to load the configurable list of Publishers.", "");

    const char *pub_prefix = "publisher.instance";
    const char *pub_suffix = "publisherId"; 

    const char *publisher_id = NULL;
    const char *publisher_lib_name = NULL;
    const char *publisher_lib_factory_name = NULL;

    char config_str[500];

    int i = -1;
    int res = 0;

    PublisherEntry *new_entry;

    while(1)
    {
       i++;

       PR_snprintf((char *)config_str, 256,"%s.%d.%s", pub_prefix,i,pub_suffix);
       publisher_id = m_cfg->GetConfigAsString(config_str,NULL); 

       if(publisher_id != NULL)
       {
           RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Found publisher id %s ", publisher_id);
           PR_snprintf((char *)config_str, 256, "%s.%d.%s",pub_prefix,i,"libraryName");

           publisher_lib_name = m_cfg->GetConfigAsString(config_str,NULL);

           if(publisher_lib_name != NULL)
           {
              RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Found publisher lib name %s ", publisher_lib_name);
              PR_snprintf((char *)config_str, 256, "%s.%d.%s",pub_prefix,i,"libraryFactory");

              publisher_lib_factory_name = m_cfg->GetConfigAsString(config_str,NULL);

             if(publisher_lib_factory_name)
             {

                 RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Found publisher lib factory name %s ", publisher_lib_factory_name);

                 PRLibrary *pb  = PR_LoadLibrary(publisher_lib_name);

                 if(pb)
                 {
                      void *sym = PR_FindSymbol(pb,publisher_lib_factory_name);

                      if(sym == NULL)
                      {

                          RA::Error(LL_PER_PDU, "RA:InitializePublishers",
                          "Failed to find symbol '%s' publisher %s error code: %d",publisher_lib_factory_name,publisher_lib_name,PR_GetError());

                          RA::Debug(LL_PER_PDU, "RA::InitializePublishers: Failed to load publish library.", "");


                          continue;
                      }
                      makepublisher make_pub = (makepublisher ) sym;

                      IPublisher *publisher = (* make_pub )();

                     if(publisher == NULL)
                     {
                       RA::Error(LL_PER_PDU, "RA:InitializePublishers",
                           "Failed to initialize publisher %s error code: %d",publisher_lib_name,PR_GetError());
                       RA::Debug(LL_PER_PDU, "RA::InitializePublishers: Failed to allocate Netkey publisher.", "");
                       continue;
                     }
                     if(publisher)
                     {
                         res = publisher->init();
                     }

                     if(!res)
                     {
                         RA::Debug(LL_PER_PDU, "RA::InitializePublishers: Failed to initialize publisher %s.", publisher_lib_name);
                         continue;                           
                     } 

                     new_entry = (PublisherEntry *) malloc(sizeof(PublisherEntry));

                     if(new_entry == NULL)
                     {

                        RA::Debug(LL_PER_PDU, "RA::InitializePublishers: Failed to allocate PublisherEntry structure", "");

                        break;

                     }
                     new_entry->id = strdup(publisher_id);
                     new_entry->publisher = publisher;
                     new_entry->publisher_lib = pb;

                     if(RA::publisher_list == NULL)
                     {
                         RA::publisher_list = new_entry;
                         new_entry->next = NULL;

                     }

                     else
                     {
                         PublisherEntry *cur = RA::publisher_list;

                         while(cur->next != NULL)
                         {
                             cur= cur->next;
                         }

                         cur->next = new_entry;
                         new_entry->next = NULL;

                     }
                         
                     RA::m_num_publishers++;
                     RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Successfully initialized publisher %s.", publisher_lib_name);
                 }
                 else
                 {
                     RA::Error(LL_PER_PDU, "RA:InitializePublishers",
                        "Failed to open library %s error code: %d",publisher_lib_name,PR_GetError());

                     RA::Debug(LL_PER_PDU, "RA::InitializePublishers"," Failed to load publish library.", "");

                     continue;

                 }
             }
             else
             {
                 continue;
             }
           }
           else
           {
               continue;

           }
       }
       else
       {
           break;
       }
    }

    if(RA::m_num_publishers == 0)
    {
        RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Did not load any publisher libraries, possibly not configured for publishing. Server continues normally... ");
        return 0;
    }
    else
    {
         RA::Debug(LL_PER_PDU, "RA::InitializePublishers:"," Loaded %d Publisher(s).", RA::m_num_publishers);

         return 1;
    }
    
}

void RA::CleanupPublishers()
{

    if(RA::m_num_publishers == 0)
      return;

    RA::Debug(LL_PER_PDU, "RA::CleanupPublishers:"," Loaded %d publishers.", RA::m_num_publishers);

    PublisherEntry *cur = RA::publisher_list;

    if(cur == NULL)
    {
         return ;
    }

    while(cur != NULL)
    {

        PublisherEntry *next =cur->next;

        if(cur)
        {

            RA::Debug(LL_PER_PDU, "RA::CleanupPublishers:"," Cleanup up publisher %s", cur->id);
            if( cur->id != NULL)
            {
                 free( cur->id );
                 cur->id = NULL;
            }

            if( cur->publisher != NULL ) {
                delete cur->publisher;
                cur->publisher = NULL;
            }

            if( cur->publisher_lib != NULL ) {
                PR_UnloadLibrary( cur->publisher_lib );
                cur->publisher_lib = NULL;
            }

            if( cur != NULL ) {
                free( cur );
                cur = NULL;
            }

            cur = next;

        }
    }

  
}

int RA::InitializeHttpConnections(const char *id, int *len, HttpConnection **conn, RA_Context *ctx) {
    char configname[256];
    char connID[100];
    CERTCertDBHandle *handle = 0;
    CERTCertificate *cert = NULL;
    int rc = 0;
    int i=0;

    *len = 0;

    // Initialize each connection
    while (1) {
        i++;
        PR_snprintf((char *)configname, 256, "conn.%s%d.hostport", id, i);
        const char *host_port = m_cfg->GetConfigAsString(configname);
        if (host_port == NULL) {
            break;
        }
        ConnectionInfo *cinfo = new ConnectionInfo();
        cinfo->BuildFailoverList(host_port);
        PR_snprintf((char *)configname, 256, "conn.%s%d.retryConnect", id, i);
        int retries = m_cfg->GetConfigAsInt(configname, 3);
        PR_snprintf((char *)configname, 256, "conn.%s%d.timeout", id, i);
        int timeout = m_cfg->GetConfigAsInt(configname, 10);
        PR_snprintf((char *)connID, 100, "%s%d", id, i);
        PR_snprintf((char *)configname, 256, "conn.%s%d.clientNickname", id, i);
        const char *clientnickname = m_cfg->GetConfigAsString(configname);

        handle = CERT_GetDefaultCertDB();
        if( handle == 0 ) {
            ctx->InitializationError( "RA::InitializeHttpConnections",
                                      __LINE__ );
            rc = -1;
            goto loser;
        }

        // (2) Since NSS has been initialized, verify the presence of the
        //     specified certificate:
        if( ( clientnickname != NULL ) &&
            ( PL_strcmp( clientnickname, "" ) != 0 ) ) {
            cert = CERT_FindCertByNickname( handle,
                                            (char *) clientnickname );
            if( cert == NULL ) {
                RA::Error( LL_PER_SERVER,
                           "RA::InitializeHttpConnections", 
                           "A %s certificate nicknamed \"%s\" "
                           "could NOT be found in the certificate "
                           "database for connection %d!",
                           id,
                           clientnickname,
                           i );
                rc = -2;
                goto loser;
            } else {
                RA::Debug( LL_PER_CONNECTION,
                           "RA::InitializeHttpConnections", 
                           "A %s certificate nicknamed \"%s\" "
                           "was found in the certificate "
                           "database for connection %d.",
                           id,
                           clientnickname,
                           i );
                CERT_DestroyCertificate( cert );
                cert = NULL;
            }
        } else {
                RA::Error( LL_PER_SERVER,
                           "RA::InitializeHttpConnections", 
                           "An empty or missing %s certificate nickname "
                           "was specified for connection %d!",
                           id,
                           i );
                rc = -3;
                goto loser;
        }

        PR_snprintf((char *)configname, 256, "conn.%s%d.SSLOn", id, i);
        bool isSSL = m_cfg->GetConfigAsBool(configname, true);
        PR_snprintf((char *)configname, 256, "conn.%s%d.keepAlive", id, i);
        bool keepAlive = m_cfg->GetConfigAsBool(configname, true);
        conn[*len] = new HttpConnection(connID, cinfo, retries, timeout, isSSL, clientnickname, keepAlive, NULL);
        (*len)++;
    }

loser:

    return rc;
}

int RA::InitializeTokendb(char *cfg_path)
{
    char *error    = NULL;
    int status;

    if (tokendbInitialized)
      return 0;

    RA::Debug("RA::InitializeTokendb", "config path = %s", cfg_path);

    if (get_tus_db_config(cfg_path) != 1) {
      RA::Debug("RA::InitializeTokendb", "get_tus_db_config failed");
      return -1;
    }

    tokendbInitialized = 1;

    RA::Debug("RA::InitializeTokendb", "Initializing TUS database");
    if( ( status = tus_db_init( &error ) ) != LDAP_SUCCESS ) {
        if( error != NULL ) {
            RA::Debug( "RA::InitializeTokendb",
                       "Token DB initialization failed: '%s'",
                       error );
            PR_smprintf_free( error );
            error = NULL;
        } else {
            RA::Debug( "RA::InitializeTokendb",
                       "Token DB initialization failed" );
        }
    }

    return status;
}

TPS_PUBLIC int RA::ra_find_tus_certificate_entries_by_order_no_vlv (char *filter,
  LDAPMessage **result, int order) 
{
    return find_tus_certificate_entries_by_order_no_vlv(filter, result, order);
}

TPS_PUBLIC int RA::ra_find_tus_certificate_entries_by_order (char *filter,
  int max, LDAPMessage **result, int order) 
{
    return find_tus_certificate_entries_by_order(filter, max, result, order);
}

TPS_PUBLIC CERTCertificate **RA::ra_get_certificates(LDAPMessage *e) {
    return get_certificates(e);
}

TPS_PUBLIC LDAPMessage *RA::ra_get_first_entry(LDAPMessage *e) {
    return get_first_entry(e);
}

TPS_PUBLIC LDAPMessage *RA::ra_get_next_entry(LDAPMessage *e) {
    return get_next_entry(e);
}

TPS_PUBLIC char **RA::ra_get_attribute_values(LDAPMessage *e, const char *p) {
    return get_attribute_values(e, p);
}

TPS_PUBLIC char *RA::ra_get_token_id(LDAPMessage *e) {
    return get_token_id(e);
}

TPS_PUBLIC char *RA::ra_get_cert_tokenType(LDAPMessage *entry) {
    return get_cert_tokenType(entry);
}

TPS_PUBLIC char *RA::ra_get_token_status(LDAPMessage *entry) {
    return get_token_status(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_cn(LDAPMessage *entry) {
    return get_cert_cn(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_attr_byname(LDAPMessage *entry, char *name) {
    return get_cert_attr_byname(entry, name);
}

TPS_PUBLIC char *RA::ra_get_cert_status(LDAPMessage *entry) {
    return get_cert_status(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_type(LDAPMessage *entry) {
    return get_cert_type(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_serial(LDAPMessage *entry) {
    return get_cert_serial(entry);
}

TPS_PUBLIC char *RA::ra_get_cert_issuer(LDAPMessage *entry) {
    return get_cert_issuer(entry);
}

TPS_PUBLIC int RA::ra_tus_has_active_tokens(char *userid) {
    return tus_has_active_tokens(userid);
}

TPS_PUBLIC char *RA::ra_get_token_reason(LDAPMessage *msg) {
    return get_token_reason(msg);
}

TPS_PUBLIC int RA::ra_get_number_of_entries(LDAPMessage *ldapResult) {
    return get_number_of_entries(ldapResult);
}

TPS_PUBLIC int RA::ra_find_tus_token_entries_no_vlv(char *filter, 
  LDAPMessage **ldapResult, int num) 
{
    return find_tus_token_entries_no_vlv(filter, ldapResult, num);
}

TPS_PUBLIC int RA::ra_find_tus_token_entries(char *filter, int maxReturns,
  LDAPMessage **ldapResult, int num) 
{
    return find_tus_token_entries(filter, maxReturns, ldapResult, num);
}

TPS_PUBLIC int RA::ra_is_tus_db_entry_disabled(char *cuid)
{
   return is_tus_db_entry_disabled(cuid);
}

TPS_PUBLIC int RA::ra_is_token_present(char *cuid)
{
    return is_token_present(cuid);
}

TPS_PUBLIC int RA::ra_is_token_pin_resetable(char *cuid)
{
    return is_token_pin_resetable(cuid);
}

TPS_PUBLIC int RA::ra_is_update_pin_resetable_policy(char *cuid)
{
    return is_update_pin_resetable_policy(cuid);
}

TPS_PUBLIC char *RA::ra_get_token_policy(char *cuid)
{
    return get_token_policy(cuid);
}

TPS_PUBLIC char *RA::ra_get_token_userid(char *cuid)
{
    return get_token_userid(cuid);
}

TPS_PUBLIC int RA::ra_update_token_policy(char *cuid, char *policy)
{
    return update_token_policy(cuid, policy);
}

TPS_PUBLIC int RA::ra_update_cert_status(char *cn, const char *status)
{
    return update_cert_status(cn, status);
}

TPS_PUBLIC int RA::ra_update_token_status_reason_userid(char *userid, char *cuid, const char *status, const char *reason, int modifyDateOfCreate)
{
    return update_token_status_reason_userid(userid, cuid, status, reason, modifyDateOfCreate);
}

TPS_PUBLIC int RA::ra_allow_token_reenroll(char *cuid)
{
    return allow_token_reenroll(cuid);
}

int RA::tdb_activity(char *ip, char *cuid, const char *op, const char *result, const char *msg, const char *userid)
{
  return add_activity(ip, cuid, op, result, msg, userid);
}

int RA::tdb_update_certificates(char* cuid, char **tokentypes, char *userid, CERTCertificate ** certificates, char **ktypes, char **origins, int numOfCerts)
{
    int rc = -1;
    LDAPMessage  *ldapResult = NULL;
    int k = 0;
    char filter[512];
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    int i = 0;

    if ((rc = find_tus_db_entry(cuid, 0, &ldapResult)) != LDAP_SUCCESS) {
	return rc;
    }

    /* update certificates */
    for (i = 0; i < numOfCerts; i++) {
      if (certificates[i] == NULL) {
         RA::Debug(LL_PER_PDU, "RA::tdb_update_certificates",
	      "no certificate found at index %d for tokendb entry: %s", i, cuid);
      } else {
         RA::Debug(LL_PER_PDU, "RA::tdb_update_certificates",
	      "cert=%x", certificates[i]);
	 
	k++;
      }
    }

    for (i = 0; i < numOfCerts; i++) {
        if (certificates[i] != NULL) {
            RA::Debug(LL_PER_PDU, "RA::tdb_update_certificates",
	        "adding cert=%x", certificates[i]);

            PR_snprintf(filter, 512, "tokenSerial=%x", DER_GetInteger(&(certificates[i])->serialNumber));
            int r = find_tus_certificate_entries_by_order_no_vlv(filter, &result, 1);
            bool found = false;
            if (r == LDAP_SUCCESS) {
                for (e = get_first_entry(result); e != NULL; e = get_next_entry(e)) {
                    char **values = get_attribute_values(e, "tokenStatus");
                    found = true;
                    RA::Debug("RA::tdb_update_certificates", "Certificate status is %s", values[0]);
                    add_certificate(cuid, origins[i], tokentypes[i], userid, certificates[i], 
                      ktypes[i], values[0]);
                    ldap_value_free(values);
                    break;
                }

                ldap_msgfree(result);
            }
            if (!found)
                add_certificate(cuid, origins[i], tokentypes[i], userid, certificates[i], 
                  ktypes[i], "active");
        }
    }

    return rc;
}

/*
 * This adds a brand new token entry to tus.
 */
int RA::tdb_add_token_entry(char *userid, char* cuid, const char *status) {
    int rc = -1;
    int r = -1;
    LDAPMessage  *ldapResult = NULL;

    if (tokendbInitialized != 1) {
      r = 0;
      goto loser;
    }

    RA::Debug(LL_PER_PDU, "RA::tdb_add_token_entry",
	      "searching for tokendb entry: %s", cuid);

    if ((rc = find_tus_db_entry(cuid, 0, &ldapResult)) != LDAP_SUCCESS) {
      /* create a new entry */
      rc = add_default_tus_db_entry(userid, "~tps", cuid, status, NULL, NULL);
      if (rc != LDAP_SUCCESS) {
	RA::Error(LL_PER_PDU, "RA:tdb_add_token_entry",
		  "failed to add tokendb entry");
	r = -1;
	goto loser;
      } else
	RA::Debug(LL_PER_PDU, "RA::tdb_add_token_entry",
		  "add tokendb entry successful");
	r = 0;
        goto loser;
    } else {
      RA::Debug(LL_PER_PDU, "RA::tdb_add_token_entry",
		"entry in tokendb exists.");

        // try to see if the userid is there
        LDAPMessage *e = ra_get_first_entry(ldapResult);
        char **uid = ra_get_attribute_values(e, "tokenUserID");

        if (uid != NULL) {
            if (uid[0] != NULL) {
                if (strlen(uid[0]) > 0 && strcmp(uid[0], userid) != 0) {
                    ldap_value_free(uid);
                    RA::Debug(LL_PER_PDU, "RA::tdb_add_token_entry",
                          "This token does not belong to this user: %s", userid);
                    r = -1;
		    goto loser;
                } else {
                    if (strlen(uid[0]) > 0 && strcmp(uid[0], userid) == 0) {
                        ldap_value_free(uid);
                        r = 0;
			goto loser;
                    }
                }
            }
            ldap_value_free(uid);
        }

        // this is the recycled token, update userid and dateOfCreate
        rc = ra_update_token_status_reason_userid(userid, cuid, status, "", 1);
	r = rc;
    }
loser:
    if (ldapResult != NULL) {
	ldap_msgfree(ldapResult);
    }
    return r;
}

/*
 * This adds entry to tokendb if entry not found
 * It is then supposed to modify entry (not yet implemented)
 */
int RA::tdb_update(const char *userid, char* cuid, char* applet_version, char *key_info, const char *state, const char *reason)
{
    int rc = -1;
    LDAPMessage  *ldapResult = NULL;
    //    char filter[255];

    if (tokendbInitialized != 1) {
	rc = 0;
	goto loser;
    }
      

    //    PR_snprintf(filter, 255, "(cn=%s)", cuid);
    RA::Debug(LL_PER_PDU, "RA::tdb_update",
	      "searching for tokendb entry: %s", cuid);

    if ((rc = find_tus_db_entry(cuid, 0, &ldapResult)) != LDAP_SUCCESS) {
      /* create a new entry */
      rc = add_default_tus_db_entry(userid, "~tps", cuid, state, applet_version, 
              key_info);
      if (rc != LDAP_SUCCESS) {
	RA::Error(LL_PER_PDU, "RA:tdb_update",
		  "failed to add tokendb entry");
	rc = -1;
	goto loser;
      } else
	RA::Debug(LL_PER_PDU, "RA::tdb_update",
		  "add tokendb entry successful");
	rc = 0;
    } else {
      RA::Debug(LL_PER_PDU, "RA::tdb_update",
		"entry in tokendb exists...should modify entry");

      /* need code to modify things such as applet version ...*/
      /* ldap modify code to follow...*/
      rc =  update_tus_db_entry ("~tps", cuid, userid, key_info, state,
                         applet_version, reason);
    }
loser:
   if (ldapResult != NULL) {
	ldap_msgfree(ldapResult);
   }
   return rc;
}

int RA::InitializeAuthentication() {
    char configname[256];
    const char *authid;
    const char *type;
    const char *authPrefix = "auth.instance";
    const char *lib = NULL;
    const char *libfactory = NULL;
    int i=-1;
    int rc=0;
    // AuthenticationEntry *authEntry; 

    while (1) {
        i++;
        PR_snprintf((char *)configname, 256, "%s.%d.authId", authPrefix, i);
        authid = m_cfg->GetConfigAsString(configname, NULL);
        if (authid != NULL) {
            RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
              "Found authentication id=%s", authid); 
            PR_snprintf((char *)configname, 256, "%s.%d.libraryName", authPrefix, i);
            lib = m_cfg->GetConfigAsString(configname, NULL);
            if (lib != NULL) {
                RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                  "Found authentication library=%s", lib); 
                PR_snprintf((char *)configname, 256, "%s.%d.libraryFactory", authPrefix, i);
                libfactory = m_cfg->GetConfigAsString(configname, NULL);
                if (libfactory != NULL) {
                    RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                      "Found authentication library factory=%s", libfactory); 
                    PRLibrary *pb  = PR_LoadLibrary(lib);
                    if (pb) {
                        RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", "Successfully loaded the library %s", lib);
                        void *sym = PR_FindSymbol(pb, libfactory);
                        if (sym == NULL) {
                            RA::Error(LL_PER_PDU, "RA::InitializeAuthentication", 
                              "Failed to find symbol '%s' in '%s' library, error code: %d", 
                              libfactory, lib, PR_GetError());
                            RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                              "Failed to load the library symbol");
                            continue;
                        }
                        makeauthentication make_auth = (makeauthentication)sym;
                        Authentication *authentication = (*make_auth)();
                        if (authentication == NULL) {
                            RA::Error(LL_PER_PDU, "RA::InitializeAuthentication", 
                              "Failed to create authentication instance with library %s, error code=%d.", 
                              lib, PR_GetError()); 
                            RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                              "Failed to create authentication instance with library %s, error code=%d.", 
                              lib, PR_GetError()); 
                            continue;
                        } else {
                            authentication->Initialize(i);
                            m_auth_list[m_auth_len] = new AuthenticationEntry();
                            m_auth_list[m_auth_len]->SetId(authid);
                            m_auth_list[m_auth_len]->SetLibrary(pb);
                            m_auth_list[m_auth_len]->SetAuthentication(authentication);
                            PR_snprintf((char *)configname, 256, "%s.%d.type", authPrefix, i);
                            type = m_cfg->GetConfigAsString(configname, NULL);
                            m_auth_list[m_auth_len]->SetType(type);
                            RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication:",
                              "Successfully initialized authentication %s.", lib);
                        }
                    } else {
                        RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                          "Failed to load the library %s: error=%d", lib, PR_GetError());
                        continue;
                    }
                } else {
                    RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                      "Failed to find the library factory %s", libfactory);
                    continue;
                }
            } else {
                RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
                  "Failed to find the library %s", lib);
                continue;
            }
            m_auth_len++;
        } else {
            break;
        }
    }

    if (m_auth_len == 0) {
        RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
          "No authentication module gets loaded, but server continues starting up...");
        rc = -1;
    } else {
        RA::Debug(LL_PER_PDU, "RA::InitializeAuthentication", 
          "Total number of authentication modules get loaded: %d", m_auth_len);
    }

    return rc;
}

int RA::Failover(HttpConnection *&conn, int len) {
    int rc = 0;
    if (m_pod_enable) {
        PR_Lock(m_pod_lock);
        if (++m_pod_curr >= len) 
            m_pod_curr = 0;
        HttpConnection *conn = NULL;
        for (int i=0; i<m_caConns_len; i++) {
            conn = m_caConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
            conn = m_drmConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
            conn = m_tksConnection[i];
            RA::SetCurrentIndex(conn, m_pod_curr);
        }
        PR_Unlock(m_pod_lock);
    } else {
        if (conn != NULL) {
            int curr = RA::GetCurrentIndex(conn);
            if (++curr >= len)
                curr = 0;
            RA::SetCurrentIndex(conn, curr);
        } else
            rc = -1;
    }
    return rc;
}
