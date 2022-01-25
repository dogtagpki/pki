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
//#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "httpd/httpd.h"
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "plhash.h"
#include "pk11func.h"
#include "cert.h"
#include "certt.h"
#include "secerr.h"
#include "base64.h"
#include "secder.h"
#include "nss.h"
#include "nssb64.h"

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
#include "main/LogFile.h"

typedef struct
{
    enum
    {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;


static ConfigStore *m_cfg = NULL;
static LogFile* m_debug_log = (LogFile *)NULL; 
static LogFile* m_error_log = (LogFile *)NULL; 

RA_Context *RA::m_ctx = NULL;
bool RA::m_pod_enable=false;
int RA::m_pod_curr = 0;
PRLock *RA::m_pod_lock = NULL;
PRLock *RA::m_verify_lock = NULL;
PRLock *RA::m_debug_log_lock = NULL;
PRLock *RA::m_error_log_lock = NULL;

PRThread *RA::m_flush_thread = (PRThread *) NULL;
size_t RA::m_bytes_unflushed =0;
size_t RA::m_buffer_size = 512;
int RA::m_flush_interval = 5;

int RA::m_debug_log_level = (int) LL_PER_SERVER;
int RA::m_error_log_level = (int) LL_PER_SERVER;
int RA::m_caConns_len = 0;
int RA::m_tksConns_len = 0;
int RA::m_drmConns_len = 0;

#define MAX_BODY_LEN 4096

#define MAX_CA_CONNECTIONS 20
#define MAX_TKS_CONNECTIONS 20
#define MAX_DRM_CONNECTIONS 20
#define MAX_AUTH_LIST_MEMBERS 20
HttpConnection* RA::m_caConnection[MAX_CA_CONNECTIONS];
HttpConnection* RA::m_tksConnection[MAX_TKS_CONNECTIONS];
HttpConnection* RA::m_drmConnection[MAX_DRM_CONNECTIONS];

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
const char *RA::CFG_ERROR_ENABLE = "logging.error.enable"; 
const char *RA::CFG_ERROR_FILENAME = "logging.error.filename"; 
const char *RA::CFG_ERROR_LEVEL = "logging.error.level";
const char *RA::CFG_SELFTEST_ENABLE = "selftests.container.logger.enable";
const char *RA::CFG_SELFTEST_FILENAME = "selftests.container.logger.fileName";
const char *RA::CFG_SELFTEST_LEVEL = "selftests.container.logger.level";
const char *RA::CFG_CHANNEL_SEC_LEVEL = "channel.securityLevel"; 
const char *RA::CFG_CHANNEL_ENCRYPTION = "channel.encryption";
const char *RA::CFG_APPLET_CARDMGR_INSTANCE_AID = "applet.aid.cardmgr_instance"; 
const char *RA::CFG_APPLET_NETKEY_INSTANCE_AID = "applet.aid.netkey_instance"; 
const char *RA::CFG_APPLET_NETKEY_FILE_AID = "applet.aid.netkey_file"; 
const char *RA::CFG_APPLET_NETKEY_OLD_INSTANCE_AID = "applet.aid.netkey_old_instance"; 
const char *RA::CFG_APPLET_NETKEY_OLD_FILE_AID = "applet.aid.netkey_old_file"; 
const char *RA::CFG_APPLET_SO_PIN = "applet.so_pin"; 
const char *RA::CFG_APPLET_DELETE_NETKEY_OLD = "applet.delete_old"; 
const char *RA::CFG_DEBUG_FILE_TYPE = "logging.debug.file.type";
const char *RA::CFG_ERROR_FILE_TYPE = "logging.error.file.type";
const char *RA::CFG_SELFTEST_FILE_TYPE = "selftests.container.logger.file.type";
const char *RA::CFG_ERROR_PREFIX = "logging.error";
const char *RA::CFG_DEBUG_PREFIX = "logging.debug";
const char *RA::CFG_SELFTEST_PREFIX = "selftests.container.logger";
const char *RA::CFG_TOKENDB_ALLOWED_TRANSITIONS = "tokendb.allowedTransitions";
const char *RA::CFG_OPERATIONS_ALLOWED_TRANSITIONS = "tps.operations.allowedTransitions";

const char *RA::CFG_AUTHS_ENABLE="auth.enable";

/* default values */
const char *RA::CFG_DEF_CARDMGR_INSTANCE_AID = "A0000000030000"; 
const char *RA::CFG_DEF_NETKEY_INSTANCE_AID = "627601FF000000"; 
const char *RA::CFG_DEF_NETKEY_FILE_AID = "627601FF0000"; 
const char *RA::CFG_DEF_NETKEY_OLD_INSTANCE_AID = "A00000000101"; 
const char *RA::CFG_DEF_NETKEY_OLD_FILE_AID = "A000000001"; 
const char *RA::CFG_DEF_APPLET_SO_PIN = "000000000000"; 

extern void BuildHostPortLists(char *host, char *port, char **hostList, 
  char **portList, int len);

static char *transitionList                  = NULL;

#define MAX_TOKEN_UI_STATE  6

enum token_ui_states  {
    TOKEN_UNINITIALIZED = 0,
    TOKEN_DAMAGED =1,
    TOKEN_PERM_LOST=2,
    TOKEN_TEMP_LOST=3,
    TOKEN_FOUND =4,
    TOKEN_TEMP_LOST_PERM_LOST =5,
    TOKEN_TERMINATED = 6
};

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
    if (m_cfg != NULL) {
        delete m_cfg;
        m_cfg = NULL;
    }
}

TPS_PUBLIC ConfigStore *RA::GetConfigStore()
{
	return m_cfg;
}

PRLock *RA::GetVerifyLock()
{
  return m_verify_lock;
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
                          bool archive, int keysize, bool isECC)
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

    if ((cuid == NULL) || (strcmp(cuid,"")==0)) {
      RA::Debug( LL_PER_CONNECTION, FN,
			"error: passed invalid cuid");
      goto loser;
    }
    if ((userid == NULL) || (strcmp(userid,"")==0)) {
      RA::Debug(LL_PER_CONNECTION, FN,
			"error: passed invalid userid");
      goto loser;
    }
    if ((desKey_s == NULL) || (strcmp(desKey_s,"")==0)) {
      RA::Debug(LL_PER_CONNECTION, FN, 
			 "error: passed invalid desKey_s");
      goto loser;
    }
    if ((connId == NULL) ||(strcmp(connId,"")==0)) {
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

    if (isECC) {
        char *eckeycurve = NULL;
        if (keysize == 521) {
            eckeycurve = "nistp521";
        } else if (keysize == 384) {
            eckeycurve = "nistp384";
        } else if (keysize == 256) {
            eckeycurve = "nistp256";
        } else {
            RA::Debug(LL_PER_CONNECTION, FN,
                "unrecognized ECC keysize %d, setting to nistp256", keysize);
            keysize = 256;
            eckeycurve = "nistp256";
        }
        PR_snprintf((char *)body, MAX_BODY_LEN, 
           "archive=%s&CUID=%s&userid=%s&keytype=EC&eckeycurve=%s&drm_trans_desKey=%s",archive?"true":"false",cuid, userid, eckeycurve, wrappedDESKey_s);
    } else {
        PR_snprintf((char *)body, MAX_BODY_LEN, 
           "archive=%s&CUID=%s&userid=%s&keysize=%d&keytype=RSA&drm_trans_desKey=%s",archive?"true":"false",cuid, userid, keysize, wrappedDESKey_s);
    }

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
            if (status_s != NULL) {
                PR_Free(status_s);
            }
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
	  if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
	    RA::Error(LL_PER_CONNECTION, FN,
				"did not get wrapped private key in DRM response");
	  } else {
	    RA::Debug(LL_PER_CONNECTION, FN,
			"got wrappedprivate key =%s", tmp);
	    *wrappedPrivateKey_s  = PL_strdup(tmp);
	  }

	  tmp = ra_pb->find_val_s("iv_param");
	  if ((tmp == NULL) || (strcmp(tmp,"")==0)) {
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

    if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
        return;
    if ((int) level >= m_debug_log_level)
		return;
    PR_Lock(m_debug_log_lock);
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    ct = PR_GetCurrentThread();
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    m_debug_log->printf("%s (length='%d')", prefix, buf->size());
    m_debug_log->printf("\n");
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    for (i=0; i<(int)buf->size(); i++) {
        m_debug_log->printf("%02x ", (unsigned char)data[i]);
        sum++; 
	if (sum == 10) {
    		m_debug_log->printf("\n");
                m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
                sum = 0;
	}
    }
    m_debug_log->write("\n");
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

 	if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
		return;
	if ((int) level >= m_debug_log_level)
		return;
	PR_Lock(m_debug_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_debug_log->vfprintf(fmt, ap); 
	m_debug_log->write("\n");
	PR_Unlock(m_debug_log_lock);
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

 	if ((m_error_log == NULL) || (!m_error_log->isOpen()))
		return;
	if ((int) level >= m_error_log_level)
		return;
	PR_Lock(m_error_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_error_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_error_log->vfprintf(fmt, ap); 
	m_error_log->write("\n");
	PR_Unlock(m_error_log_lock);
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

PK11SymKey *RA::FindSymKeyByName( PK11SlotInfo *slot, char *keyname) {
char       *name       = NULL;
    PK11SymKey *foundSymKey= NULL;
    PK11SymKey *firstSymKey= NULL;
    PK11SymKey *sk  = NULL;
    PK11SymKey *nextSymKey = NULL;
    secuPWData  pwdata;

    pwdata.source   = secuPWData::PW_NONE;
    pwdata.data     = (char *) NULL;
    if (keyname == NULL)
    {
        goto cleanup;
    }
    if (slot== NULL)
    {
        goto cleanup;
    }
    /* Initialize the symmetric key list. */
    firstSymKey = PK11_ListFixedKeysInSlot( slot , NULL, ( void *) &pwdata );
    /* scan through the symmetric key list for a key matching our nickname */
    sk = firstSymKey;
    while( sk != NULL )
    {
        /* get the nickname of this symkey */
        name = PK11_GetSymKeyNickname( sk );

        /* if the name matches, make a 'copy' of it */
        if ( name != NULL && !strcmp( keyname, name ))
        {
            if (foundSymKey == NULL)
            {
                foundSymKey = PK11_ReferenceSymKey(sk);
            }
            PORT_Free(name);
        }

        sk = PK11_GetNextSymKey( sk );
    }

    /* We're done with the list now, let's free all the keys in it
       It's okay to free our key, because we made a copy of it */

    sk = firstSymKey;
    while( sk != NULL )
    {
        nextSymKey = PK11_GetNextSymKey(sk);
        PK11_FreeSymKey(sk);
        sk = nextSymKey;
    }

    cleanup:
    return foundSymKey;
}

bool RA::isAlgorithmECC(BYTE alg)
{
    bool result = false;

    if (alg == ALG_EC_F2M || alg == ALG_EC_FP)
       result = true;

    RA::Debug(LL_PER_SERVER, "RA::isAlgorithmECC", " alg: %d result: %d", alg, result);

    return result;
}
