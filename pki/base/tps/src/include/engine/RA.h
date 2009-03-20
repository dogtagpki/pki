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

#ifndef RA_H
#define RA_H

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

#include "pk11func.h"
#include "engine/audit.h"
#include "ldap.h"
#include "main/Base.h"
#include "main/ConfigStore.h"
#include "main/Buffer.h"
#include "main/PublishEntry.h"
#include "main/AuthenticationEntry.h"
#include "authentication/Authentication.h"
#include "apdu/APDU.h"
#include "main/RA_Context.h"
#include "channel/Secure_Channel.h"
#include "cms/HttpConnection.h"
#include "cms/ConnectionInfo.h"
#include  "publisher/IPublisher.h"

/*
 *
 * LL_PER_SERVER = 4        these messages will occur only once during the
 *                          entire invocation of the server, e.g. at startup
 *                          or shutdown time., reading the conf parameters.
 *                          Perhaps other infrequent events relating to
 *                          failing over of CA, TKS, too
 *
 * LL_PER_CONNECTION = 6    these messages happen once per connection - most
 *                          of the log events will be at this level
 *
 * LL_PER_PDU = 8           these messages relate to PDU processing. If you
 *                          have something that is done for every PDU, such
 *                          as applying the MAC, it should be logged at this
 *                          level
 *
 * LL_ALL_DATA_IN_PDU = 9   dump all the data in the PDU - a more chatty
 *                          version of the above
 */
enum RA_Log_Level {
	LL_PER_SERVER = 4,
	LL_PER_CONNECTION = 6,
	LL_PER_PDU = 8,
	LL_ALL_DATA_IN_PDU = 9
};


#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/* For now, this value must correspond exactly to the successful exit */
/* status of RA::Initialize( char *cfg_path, RA_Context *ctx ).       */
#define RA_INITIALIZATION_SUCCESS 1

typedef char NSSUTF8;

class RA
{
  public:
	  RA();
	  ~RA();
  public:
          static bool IsAuditEventSelected(const char *auditEvent);
          static void getLastSignature();
	  static int IsTokendbInitialized();
	  static int IsTpsConfigured();
	  TPS_PUBLIC static int Initialize(char *cfg_path, RA_Context *ctx);
//	  TPS_PUBLIC static int InitializeInChild(RA_Context *ctx);
	  TPS_PUBLIC static int InitializeInChild(RA_Context *ctx, int nSignedAuditInitCount);
	  TPS_PUBLIC static int Shutdown();
  public:

 	  static PK11SymKey *ComputeSessionKey(RA_Session *session,
                                           Buffer &CUID,
                                           Buffer &keyinfo,
                                           Buffer &card_challenge,
                                           Buffer &host_challenge,
                                           Buffer **host_cryptogram,
                                           Buffer &card_cryptogram,
                                           PK11SymKey **encSymKey,
                                           char** drm_kekSessionKey_s,
                                           char** kek_kekSessionKey_s,
                                           char **keycheck_s,
                                           const char *connId);
	  static void ServerSideKeyGen(RA_Session *session, const char* cuid,
                                   const char *userid, char* kekSessionKey_s,
		                           char **publickey_s,
                                   char **wrappedPrivateKey_s,
                                   char **ivParam_s, const char *connId,
                                   bool archive, int keysize);
	  static void RecoverKey(RA_Session *session, const char* cuid,
                             const char *userid, char* kekSessionKey_s,
                             char *cert_s, char **publickey_s,
                             char **wrappedPrivateKey_s, const char *connId);

	  static Buffer *ComputeHostCryptogram(Buffer &card_challenge, Buffer &host_challenge);
  public:
	  TPS_PUBLIC static ConfigStore *GetConfigStore();
  public:
	  TPS_PUBLIC static void Audit(const char *func_name, const char *fmt, ...);
	  TPS_PUBLIC static void Error(const char *func_name, const char *fmt, ...);
          TPS_PUBLIC static void Debug(const char *func_name, const char *fmt, ...);
	  TPS_PUBLIC static void DebugBuffer(const char *func_name, const char *prefix, Buffer *buf);
	  TPS_PUBLIC static void Audit(RA_Log_Level level, const char *func_name, const char *fmt, ...);
	  TPS_PUBLIC static void Error(RA_Log_Level level, const char *func_name, const char *fmt, ...);
	  TPS_PUBLIC static void Debug(RA_Log_Level level, const char *func_name, const char *fmt, ...);
	  static void DebugBuffer(RA_Log_Level level, const char *func_name, const char *prefix, Buffer *buf);
  private:
	  static void AuditThis(RA_Log_Level level, const char *func_name, const char *fmt, va_list ap);
	  static void ErrorThis(RA_Log_Level level, const char *func_name, const char *fmt, va_list ap);
	  static void DebugThis(RA_Log_Level level, const char *func_name, const char *fmt, va_list ap);
  public:
          static int InitializeTokendb(char *cfg_path);
          static int InitializeSignedAudit();
          static PRLock *GetVerifyLock();
          TPS_PUBLIC static CERTCertificate **ra_get_certificates(LDAPMessage *e);
          TPS_PUBLIC static LDAPMessage *ra_get_first_entry(LDAPMessage *e);
          TPS_PUBLIC static LDAPMessage *ra_get_next_entry(LDAPMessage *e);
          TPS_PUBLIC static char **ra_get_attribute_values(LDAPMessage *e, const char *p);
          TPS_PUBLIC static char *ra_get_cert_attr_byname(LDAPMessage *e, char *name);
          TPS_PUBLIC static char *ra_get_token_id(LDAPMessage *e);
      TPS_PUBLIC static char *ra_get_cert_tokenType(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_token_status(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_cert_cn(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_cert_status(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_cert_type(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_cert_serial(LDAPMessage *entry);
      TPS_PUBLIC static char *ra_get_cert_issuer(LDAPMessage *entry);
          TPS_PUBLIC static int ra_tus_has_active_tokens(char *userid);
          TPS_PUBLIC static char *ra_get_token_reason(LDAPMessage *msg);
          TPS_PUBLIC static int ra_get_number_of_entries(LDAPMessage *ldapResult);
          TPS_PUBLIC static int ra_find_tus_token_entries(char *filter,
            int maxReturns, LDAPMessage **ldapResult, int num);
          TPS_PUBLIC static int ra_find_tus_token_entries_no_vlv(char *filter,
            LDAPMessage **ldapResult, int num);
	  TPS_PUBLIC static int ra_is_tus_db_entry_disabled(char *cuid);
	  TPS_PUBLIC static int ra_is_token_pin_resetable(char *cuid);
	  TPS_PUBLIC static int ra_is_token_present(char *cuid);
	  TPS_PUBLIC static int ra_allow_token_reenroll(char *cuid);
	  TPS_PUBLIC static int ra_is_update_pin_resetable_policy(char *cuid);
	  TPS_PUBLIC static char *ra_get_token_policy(char *cuid);
	  TPS_PUBLIC static char *ra_get_token_userid(char *cuid);
	  TPS_PUBLIC static int ra_update_token_policy(char *cuid, char *policy);
      TPS_PUBLIC static int ra_update_cert_status(char *cn, const char *status);
      TPS_PUBLIC static int ra_find_tus_certificate_entries_by_order(
        char *filter, int num, LDAPMessage **msg, int order);
      TPS_PUBLIC static int ra_find_tus_certificate_entries_by_order_no_vlv(
        char *filter, LDAPMessage **msg, int order);
      TPS_PUBLIC static void ra_tus_print_integer(char *out, SECItem *data);
      TPS_PUBLIC static int ra_update_token_status_reason_userid(char *userid,
        char *cuid, const char *status, const char *reason, int modifyDateOfCreate);
          static int tdb_add_token_entry(char *userid, char* cuid, const char *status, const char *token_type);
	  static int tdb_update(const char *userid, char *cuid, char *applet_version, char *key_info, const char *state, const char *reason, const char * token_type);
	  static int tdb_update_certificates(char *cuid, char **tokentypes, char *userid, CERTCertificate **certificates, char **ktypes, char **origins, int numOfCerts);
	  static int tdb_activity(char *ip, char *cuid, const char *op, const char *result, const char *msg, const char *userid, const char *token_type);
	  static int testTokendb();
          static int InitializeAuthentication();
          static AuthenticationEntry *GetAuth(const char *id);
  public:
          static HttpConnection *GetCAConn(const char *id);
          static void ReturnCAConn(HttpConnection *conn);
          static HttpConnection *GetTKSConn(const char *id);
          static void ReturnTKSConn(HttpConnection *conn);

          static HttpConnection *GetDRMConn(const char *id);
          static void ReturnDRMConn(HttpConnection *conn);
          static int GetCurrentIndex(HttpConnection *conn);

  public:

          static void SetPodIndex(int index);
          static int GetPodIndex();
          TPS_PUBLIC static int GetAuthCurrentIndex();
          static void SetAuthCurrentIndex(int index);
          TPS_PUBLIC static PRLock *GetAuthLock();
          TPS_PUBLIC static void IncrementAuthCurrentIndex(int len);
	  static void SetGlobalSecurityLevel(SecurityLevel sl);
	  static SecurityLevel GetGlobalSecurityLevel();
  public: /* default values */
	  static const char *CFG_DEF_CARDMGR_INSTANCE_AID;
	  static const char *CFG_DEF_NETKEY_INSTANCE_AID;
	  static const char *CFG_DEF_NETKEY_FILE_AID;
	  static const char *CFG_DEF_NETKEY_OLD_INSTANCE_AID;
	  static const char *CFG_DEF_NETKEY_OLD_FILE_AID;
	  static const char *CFG_DEF_APPLET_SO_PIN;
  public:
	  static const char *CFG_APPLET_DELETE_NETKEY_OLD;
	  static const char *CFG_APPLET_CARDMGR_INSTANCE_AID;
	  static const char *CFG_APPLET_NETKEY_INSTANCE_AID;
	  static const char *CFG_APPLET_NETKEY_FILE_AID;
	  static const char *CFG_APPLET_NETKEY_OLD_INSTANCE_AID;
	  static const char *CFG_APPLET_NETKEY_OLD_FILE_AID;
	  static const char *CFG_APPLET_SO_PIN;
	  static const char *CFG_DEBUG_ENABLE;
	  static const char *CFG_DEBUG_FILENAME;
          static const char *CFG_DEBUG_LEVEL;
	  static const char *CFG_AUDIT_ENABLE;
	  static const char *CFG_AUDIT_FILENAME;
	  static const char *CFG_SIGNED_AUDIT_FILENAME;
          static const char *CFG_AUDIT_LEVEL;
          static const char *CFG_AUDIT_SIGNED;
          static const char *CFG_AUDIT_SIGNING_CERT_NICK;
          static const char *CFG_ERROR_LEVEL;
	  static const char *CFG_ERROR_ENABLE;
	  static const char *CFG_ERROR_FILENAME;
	  static const char *CFG_CHANNEL_SEC_LEVEL;
	  static const char *CFG_CHANNEL_ENCRYPTION;

      static const char *CFG_AUTHS_ENABLE;
      static const char *CFG_AUTHS_CURRENTIMPL;
      static const char *CFG_AUTHS_PLUGINS_NUM;
      static const char *CFG_AUTHS_PLUGIN_NAME;

      static const char *CFG_IPUBLISHER_LIB;
      static const char *CFG_IPUBLISHER_FACTORY;

  public:
	  static const char *TKS_RESPONSE_STATUS;
	  static const char *TKS_RESPONSE_SessionKey;
	  static const char *TKS_RESPONSE_EncSessionKey;
	  static const char *TKS_RESPONSE_KEK_DesKey;
	  static const char *TKS_RESPONSE_DRM_Trans_DesKey;
	  static const char *TKS_RESPONSE_HostCryptogram;

  public:
          static int m_used_tks_conn;
          static int m_used_ca_conn;

          static int m_used_drm_conn;
          static HttpConnection* m_drmConnection[];
          static int m_drmConns_len;
          static int m_pod_curr;
          static int m_auth_curr;
          static bool m_pod_enable;
          static PRLock *m_verify_lock;
          static PRLock *m_pod_lock;
          static PRLock *m_auth_lock;
          static PRLock *m_error_log_lock;
          static PRLock *m_audit_log_lock;
          static PRLock *m_debug_log_lock;
          static int m_audit_log_level;
          static int m_debug_log_level;
          static int m_error_log_level;
          static bool m_audit_signed;
          static SECKEYPrivateKey *m_audit_signing_key;
          static char *m_last_audit_signature;
          static SECOidTag m_audit_signAlgTag;
      static HttpConnection* m_caConnection[];
      static HttpConnection* m_tksConnection[];
      static int m_caConns_len;
      static int m_tksConns_len;
      static int m_auth_len;
      static AuthenticationEntry *m_auth_list[];
	  static SecurityLevel m_global_security_level;
      static void SetCurrentIndex(HttpConnection *&conn, int index);

          static PublisherEntry *publisher_list;
          static int m_num_publishers;


          static PublisherEntry *getPublisherById(const char *publisher_id);
          static int InitializePublishers();
          static int InitializeHttpConnections(const char *id, int *len, HttpConnection **conn, RA_Context *ctx);
          static void CleanupPublishers();
        static int Failover(HttpConnection *&conn, int len);        
};

#endif /* RA_H */
