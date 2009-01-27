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

#include <string.h>

#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "engine/RA.h"
#include "channel/Secure_Channel.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "processor/RA_Processor.h"
#include "processor/RA_Format_Processor.h"
#include "cms/CertEnroll.h"
#include "httpClient/httpc/response.h"
#include "main/Memory.h"
#include "tus/tus_db.h"
#include "ldap.h"

#define OP_PREFIX "op.format"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a processor for handling upgrade operation.
 */
TPS_PUBLIC RA_Format_Processor::RA_Format_Processor ()
{
}

/**
 * Destructs upgrade processor.
 */
TPS_PUBLIC RA_Format_Processor::~RA_Format_Processor ()
{
}

/**
 * Processes the current session.
 */
TPS_PUBLIC RA_Status RA_Format_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    char configname[256];
    char *cuid = NULL;
    char *msn = NULL;
    const char *tokenType = NULL;
    PRIntervalTime start, end;
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    Secure_Channel *channel = NULL;
    Buffer kdd;
    AuthParams *login = NULL;
    // char *new_pin = NULL;
    const char *applet_dir;
    bool upgrade_enc = false;
    SecurityLevel security_level = SECURE_MSG_MAC_ENC;

    Buffer *buildID = NULL;
    Buffer *token_status = NULL;
    const char* required_version = NULL;
    const char *appletVersion = NULL;
    const char *final_applet_version = NULL;
    const char *userid = PL_strdup( "" );
    // BYTE se_p1 = 0x00;
    // BYTE se_p2 = 0x00;
    const char *expected_version;
    int requiredV = 0;
    const char *tksid = NULL;
    const char *authid = NULL;
    AuthParams *authParams = NULL;
    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    Buffer *cplc_data = NULL;
    char activity_msg[4096];
    LDAPMessage *ldapResult = NULL;
    LDAPMessage *e = NULL;
    LDAPMessage  *result = NULL;
    char serial[100];
    char *statusString;
    char filter[512];
    int statusNum;
    Buffer curKeyInfo;
    BYTE curVersion;
    bool tokenFound = false;
    int finalKeyVersion = 0;
    char *keyVersion = NULL;
    char *xuserid = NULL;

    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
		   RA::CFG_APPLET_CARDMGR_INSTANCE_AID, 
		   RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_NETKEY_INSTANCE_AID, 
		    RA::CFG_DEF_NETKEY_INSTANCE_AID);
    Buffer key_data_set;
    Buffer token_cuid;
    Buffer token_msn;
    RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
	      "Begin upgrade process");

    BYTE major_version = 0x0;
    BYTE minor_version = 0x0;
    BYTE app_major_version = 0x0;
    BYTE app_minor_version = 0x0;
        const char *connid = NULL;
        int upgrade_rc;

    start = PR_IntervalNow();

    RA::Debug("RA_Format_Processor::Process", "Client %s",                       session->GetRemoteIP());


    SelectApplet(session, 0x04, 0x00, CardManagerAID);
    cplc_data = GetData(session);
    if (cplc_data == NULL) {
          RA::Error("RA_Format_Processor::Process",
                        "Get Data Failed");
          status = STATUS_ERROR_SECURE_CHANNEL;
          goto loser;
    }
    RA::DebugBuffer("RA_Format_Processor::process", "CPLC Data = ", 
                        cplc_data);
    if (cplc_data->size() < 47) {
          RA::Error("RA_Format_Processor::Process",
                        "Invalid CPLC Size");
          status = STATUS_ERROR_SECURE_CHANNEL;
          goto loser;
    }
    token_cuid =  Buffer(cplc_data->substr(3,4)) +
             Buffer(cplc_data->substr(19,2)) +
             Buffer(cplc_data->substr(15,4));
    RA::DebugBuffer("RA_Format_Processor::process", "Token CUID= ",
                        &token_cuid);
    cuid = Util::Buffer2String(token_cuid);

    token_msn = Buffer(cplc_data->substr(41, 4));
    RA::DebugBuffer("RA_Format_Processor::process", "Token MSN= ",
                        &token_msn);
    msn = Util::Buffer2String(token_msn);


    /**
     * Checks if the netkey has the required applet version.
     */
    SelectApplet(session, 0x04, 0x00, NetKeyAID);
    token_status = GetStatus(session, 0x00, 0x00);
    if (token_status == NULL) {
        major_version = 0;
        minor_version = 0;
        app_major_version = 0x0;
        app_minor_version = 0x0;
    } else {
        major_version = ((BYTE*)*token_status)[0];
        minor_version = ((BYTE*)*token_status)[1];
        app_major_version = ((BYTE*)*token_status)[2];
        app_minor_version = ((BYTE*)*token_status)[3];
    }

    RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
	      "Major=%d Minor=%d", major_version, minor_version);
    RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
	      "Applet Major=%d Applet Minor=%d", app_major_version, app_minor_version);

    if (!GetTokenType(OP_PREFIX, major_version,
                    minor_version, cuid, msn,
                    extensions, status, tokenType)) {
        goto loser;
    }


    if (RA::ra_is_token_present(cuid)) {
       RA::Debug("RA_Format_Processor::Process",
	      "Found token %s", cuid);

      if (RA::ra_is_tus_db_entry_disabled(cuid)) {
        RA::Error("RA_Format_Processor::Process",
                        "CUID %s Disabled", cuid);
        status = STATUS_ERROR_DISABLED_TOKEN;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "token disabled", "", tokenType);
        goto loser;
      }
    } else {
       RA::Debug("RA_Format_Processor::Process",
	      "Not Found token %s", cuid);
      // This is a new token. We need to check our policy to see
      // if we should allow enrollment. raidzilla #57414
      PR_snprintf((char *)configname, 256, "%s.allowUnknownToken",
            OP_PREFIX);
      if (!RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
        RA::Error("Process", "CUID %s Format Unknown Token", cuid);
        status = STATUS_ERROR_DISABLED_TOKEN;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "unknown token disallowed", "", tokenType);
        goto loser;
      }

    }

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn",
                    OP_PREFIX, tokenType);
    tksid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (tksid == NULL) {
        RA::Error("RA_Format_Processor::Process",
                        "TKS Connection Parameter %s Not Found", configname);
        status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
        goto loser;
    }

    buildID = GetAppletVersion(session);
    if (buildID == NULL) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.emptyToken.enable", OP_PREFIX, tokenType);
        if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
            appletVersion = PL_strdup( "" );
        } else {
            RA::Error("RA_Format_Processor::Process", 
              "no applet found and applet upgrade not enabled");
            status = STATUS_ERROR_SECURE_CHANNEL;		 
            RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "secure channel not established", "", tokenType);
            goto loser;
        }
    } else {
      char * buildid =  Util::Buffer2String(*buildID);
      RA::Debug("RA_Format_Processor", "buildid = %s", buildid);
      char version[13];
      PR_snprintf((char *) version, 13,
		  "%x.%x.%s", app_major_version, app_minor_version,
		  buildid);
      appletVersion = strdup(version);
    }

    final_applet_version = strdup(appletVersion);
    RA::Debug("RA_Format_Processor", "final_applet_version = %s", final_applet_version);

    /**
     * Checks if we need to upgrade applet. 
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.requiredVersion", OP_PREFIX, tokenType);

    required_version = RA::GetConfigStore()->GetConfigAsString(
      configname);
    expected_version = PL_strdup(required_version);

    if (expected_version == NULL) {
        RA::Error("RA_Format_Processor::Process", 
          "upgrade.version not found");
        status = STATUS_ERROR_MISCONFIGURATION;		 
        goto loser;
    }
    /* upgrade applet */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.directory", OP_PREFIX, tokenType);
    applet_dir = RA::GetConfigStore()->GetConfigAsString(configname);
    if (applet_dir == NULL) {
        RA::Error(LL_PER_PDU, "RA_Processor::UpdateApplet",
          "Failed to get %s", applet_dir);
        status = STATUS_ERROR_MISCONFIGURATION;		 
        goto loser;
    }

    PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
        if (extensions != NULL &&
               extensions->GetValue("extendedLoginRequest") != NULL)
        {
                   RA::Debug("RA_Enroll_Processor::RequestUserId",
                "Extended Login Request detected");
                   AuthenticationEntry *entry = GetAuthenticationEntry(
            OP_PREFIX, configname, tokenType);
                   char **params = NULL;
                   char pb[1024];
                   char *locale = NULL;
           if (extensions != NULL &&
               extensions->GetValue("locale") != NULL)
                   {
                           locale = extensions->GetValue("locale");
                   } else {
                           locale = ( char * ) "en"; /* default to english */
                   }
                   int n = entry->GetAuthentication()->GetNumOfParamNames();
                   if (n > 0) {
                       RA::Debug("RA_Enroll_Processor::RequestUserId",
                "Extended Login Request detected n=%d", n);
                       params = (char **) PR_Malloc(n);
                       for (int i = 0; i < n; i++) {
                         sprintf(pb,"id=%s&name=%s&desc=%s&type=%s&option=%s",
                             entry->GetAuthentication()->GetParamID(i),
                             entry->GetAuthentication()->GetParamName(i, locale),
                             entry->GetAuthentication()->GetParamDescription(i,
locale),
                             entry->GetAuthentication()->GetParamType(i),
                             entry->GetAuthentication()->GetParamOption(i)
                             );
                         params[i] = PL_strdup(pb);
                   RA::Debug("RA_Enroll_Processor::RequestUserId",
                "params[i]=%s", params[i]);
                       }
                   }
                   RA::Debug("RA_Enroll_Processor::RequestUserId", "Extended Login Request detected calling RequestExtendedLogin() locale=%s", locale);
                                                                                
                   char *title = PL_strdup(entry->GetAuthentication()->GetTitle(locale));
                   RA::Debug("RA_Enroll_Processor::RequestUserId", "title=%s", title);
                   char *description = PL_strdup(entry->GetAuthentication()->GetDescription(locale));
                   RA::Debug("RA_Enroll_Processor::RequestUserId", "description=%s", description);
           login = RequestExtendedLogin(session, 0 /* invalid_pw */, 0 /* blocked */, params, n, title, description);
                             
                   RA::Debug("RA_Enroll_Processor::RequestUserId",
    "Extended Login Request detected calling RequestExtendedLogin() login=%x", login);
        } else {
          login = RequestLogin(session, 0 /* invalid_pw */, 0 /* blocked */);
        }
        if (login == NULL) {
            RA::Error("RA_Format_Processor::Process",
              "login not provided");
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "login not found", "", tokenType);
            goto loser;
        }
        if( userid != NULL ) {
          PR_Free( (char *) userid );
          userid = NULL;
        }
        if (login->GetUID() == NULL) {
          userid = NULL;
        } else {
          userid = PL_strdup( login->GetUID() );
        } 
    }

    // send status update to the client
    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 2 /* progress */, 
	                          "PROGRESS_START_AUTHENTICATION");
    }

    PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, false)) {
        if (login == NULL) {
            RA::Error("RA_Format_Processor::Process", "Login Request Disabled. Authentication failed.");
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "login not found", "", tokenType);
            goto loser;
        }

        PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, tokenType);
        authid = RA::GetConfigStore()->GetConfigAsString(configname);
        if (authid == NULL) {
            status = STATUS_ERROR_LOGIN;		 
            RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "login not found", "", tokenType);
            goto loser;
	}
        AuthenticationEntry *auth = RA::GetAuth(authid);

        if(auth == NULL)
        {
            RA::Error("RA_Format_Processor::Process", "Authentication manager is NULL . Authentication failed.");
            status = STATUS_ERROR_LOGIN;
            goto loser;
        }

        char *type = auth->GetType();
        if (type == NULL) {
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "authentication is missing param type", "", tokenType);
            goto loser;
        }
        if (strcmp(type, "LDAP_Authentication") == 0) {
            RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
                    "LDAP_Authentication is invoked.");
            int passwd_retries = auth->GetAuthentication()->GetNumOfRetries();
            int retries = 0;
            authParams = new AuthParams();
            authParams->SetUID(login->GetUID());
            authParams->SetPassword(login->GetPassword());
            rc = auth->GetAuthentication()->Authenticate(authParams);

            RA::Debug("RA_Format_Processor::Process",
              "Authenticate returns: %d", rc);

            while ((rc == -2 || rc == -3) && (retries < passwd_retries)) {
                login = RequestLogin(session, 0 /* invalid_pw */, 0 /* blocked */);
                retries++;
                if (login == NULL || login->GetUID() == NULL) {
                  RA::Error("RA_Format_Processor::Process", "Authentication failed.");
                  status = STATUS_ERROR_LOGIN;
                  RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "authentication error", "", tokenType);
                  goto loser;
                }
                authParams->SetUID(login->GetUID());
                authParams->SetPassword(login->GetPassword());
                rc = auth->GetAuthentication()->Authenticate(authParams);
            }

            if (rc == -1) {
                RA::Error("RA_Format_Processor::Process", "Authentication failed.");
                status = STATUS_ERROR_LDAP_CONN;
                RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process", "Authentication status = %d", status);
                RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "authentication error", "", tokenType);
                goto loser;
            }

            if (rc == -2 || rc == -3) {
                RA::Error("RA_Format_Processor::Process", "Authentication failed.");
                status = STATUS_ERROR_LOGIN;
                RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process", "Authentication status = %d", status);
                RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "authentication error", "", tokenType);
                goto loser;
            }

            RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process", "Authentication successful.");
        } else {
            RA::Error("RA_Format_Processor::Process", "No Authentication type was found.");
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "authentication error", "", tokenType);
            goto loser;
        }
    } else {
        RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
          "Authentication has been disabled.");
    }

    // check if it is the token owner
   xuserid = RA::ra_get_token_userid(cuid);
   if (xuserid != NULL && strcmp(xuserid, "") != 0) {
     if (login != NULL) {
       if (strcmp(login->GetUID(), xuserid) != 0) {
          RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
            "Token owner mismatched");
          status = STATUS_ERROR_LOGIN;
          goto loser;
       }
     }
   }

    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 10 /* progress */, 
	                          "PROGRESS_APPLET_UPGRADE");
    }

    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.encryption", OP_PREFIX, tokenType);
    upgrade_enc = RA::GetConfigStore()->GetConfigAsBool(configname, true);
    if (!upgrade_enc)
        security_level = SECURE_MSG_MAC;
    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
    connid = RA::GetConfigStore()->GetConfigAsString(configname);
    upgrade_rc = UpgradeApplet(session, OP_PREFIX, (char*)tokenType, major_version, 
      minor_version, expected_version, applet_dir, security_level, connid,
			       extensions, 10, 90);
    if (upgrade_rc != 1) {
        RA::Debug("RA_Format_Processor::Process", 
          "applet upgrade failed");
        status = STATUS_ERROR_UPGRADE_APPLET;		 
        /**
         * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
         */
        SelectApplet(session, 0x04, 0x00, NetKeyAID);
        RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "applet upgrade error", "", tokenType);
        goto loser;
    } 
    RA::Audit("Upgrade", 
      "op='applet_upgrade' app_ver='%s' new_app_ver='%s'", 
      appletVersion, expected_version);
    final_applet_version = expected_version;

    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 90 /* progress */, 
	                          "PROGRESS_KEY_UPGRADE");
    }

    // add issuer info to the token
    PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.enable", 
          OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        channel = SetupSecureChannel(session, 0x00,
                  defKeyIndex  /* default key index */, connid);
        rc = channel->ExternalAuthenticate();
        if (channel != NULL) {
            char issuer[224];
            for (int i = 0; i < 224; i++) {
              issuer[i] = 0;
            }
            PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.value", 
               OP_PREFIX, tokenType);
            char *issuer_val = (char*)RA::GetConfigStore()->GetConfigAsString(
                                   configname);
            sprintf(issuer, "%s", issuer_val);
            RA::Debug("RA_Format_Processor", "Set Issuer Info %s", issuer_val);
            Buffer *info = new Buffer((BYTE*)issuer, 224);
            rc = channel->SetIssuerInfo(info);
        }
    }

    /**
     * Checks if the netkey has the required key version.
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {

        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        requiredV = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
        PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
        tksid = RA::GetConfigStore()->GetConfigAsString(configname);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        channel = SetupSecureChannel(session, requiredV,
                   defKeyIndex  /* default key index */, tksid);
        if (channel == NULL) {
            /**
             * Select Card Manager for Put Key operation.
             */
            SelectApplet(session, 0x04, 0x00, CardManagerAID);
	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 92 /* progress */, 
	                          "PROGRESS_SETUP_SECURE_CHANNEL");
	    }
            /* if the key of the required version is
             * not found, create them.
             */ 
        PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
        int defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
            channel = SetupSecureChannel(session, 
                  defKeyVer,  /* default key version */
                  defKeyIndex  /* default key index */, tksid);
 
            if (channel == NULL) {
                RA::Error("RA_Upgrade_Processor::Process", 
                  "failed to establish secure channel");
                status = STATUS_ERROR_SECURE_CHANNEL;		 
                goto loser;
            }

	    // send status update to the client
	    if (extensions != NULL && 
		extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 94 /* progress */, 
	                          "PROGRESS_EXTERNAL_AUTHENTICATE");
	    }

            rc = channel->ExternalAuthenticate();

            PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
            int v = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
            curKeyInfo = channel->GetKeyInfoData();
            BYTE nv[2] = { v, 0x01 };
            Buffer newVersion(nv, 2);
            PR_snprintf((char *)configname,  256,"%s.%s.tks.conn", OP_PREFIX, tokenType);
            connid = RA::GetConfigStore()->GetConfigAsString(configname);
            rc = CreateKeySetData(
              channel->GetKeyDiversificationData(), 
              curKeyInfo,
              newVersion,
              key_data_set, connid);
            if (rc != 1) {
                RA::Error("RA_Format_Processor::Process", 
                  "failed to create new key set");
                status = STATUS_ERROR_CREATE_CARDMGR;
                RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "create key set error", "", tokenType);
                goto loser;
            }

            curVersion = ((BYTE*)curKeyInfo)[0];


	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 96 /* progress */, 
	                          "PROGRESS_PUT_KEYS");
	    }

            BYTE curIndex = ((BYTE*)curKeyInfo)[1];
            rc = channel->PutKeys(session, 
                  curVersion,
                  curIndex,
                  &key_data_set);
            RA::Audit("Format", "op='key_change_over' app_ver='%s' cuid='%s' old_key_ver='%02x01' new_key_ver='%02x01'", 
              final_applet_version, cuid, curVersion, 
              ((BYTE*)newVersion)[0]);


             finalKeyVersion = ((int) ((BYTE *)newVersion)[0]);
            /**
	     * Re-select Net Key Applet.
	     */
            SelectApplet(session, 0x04, 0x00, NetKeyAID);
            PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
            requiredV = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
            PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
            tksid = RA::GetConfigStore()->GetConfigAsString(configname);
            if( channel != NULL ) {
                delete channel;
                channel = NULL;
            }
	    // send status update to the client
	    if (extensions != NULL && 
	             extensions->GetValue("statusUpdate") != NULL) {
	               StatusUpdate(session, 98 /* progress */, 
	                          "PROGRESS_SETUP_SECURE_CHANNEL");
	    }


            channel = SetupSecureChannel(session, requiredV,
              defKeyIndex  /* default key index */, tksid);
            if (channel == NULL) {
                RA::Error("RA_Format_Processor::Process", 
			      "failed to establish secure channel after reselect");
                status = STATUS_ERROR_CREATE_CARDMGR;
                RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "failure", "secure channel not established", "", tokenType);
                goto loser;
            }
        }     
    }

    PR_snprintf((char *)filter, 256, "(cn=%s)", cuid);
    rc = RA::ra_find_tus_token_entries(filter, 100, &result, 0);
    if (rc == 0) {
        for (e = RA::ra_get_first_entry(result); e != NULL; e = RA::ra_get_next_entry(e)) {
            tokenFound = true;
            break;
        }
        if (result != NULL)
            ldap_msgfree(result);
    }

    // get keyVersion
    if (channel != NULL) {
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    // need to revoke all the certificates on this token
    if (tokenFound) {
        PR_snprintf((char *)filter, 256, "(tokenID=%s)", cuid);
        rc = RA::ra_find_tus_certificate_entries_by_order(filter, 100, &result, 1);
        if (rc == 0) {
            CertEnroll *certEnroll = new CertEnroll();
            for (e = RA::ra_get_first_entry(result); e != NULL; e = RA::ra_get_next_entry(e)) {
                char *attr_status = RA::ra_get_cert_status(e);
                if (strcmp(attr_status, "revoked") == 0) {
                    if (attr_status != NULL) {
                        PL_strfree(attr_status);
                        attr_status = NULL;
                    }
                    continue;
                }
                char *attr_serial= RA::ra_get_cert_serial(e);
                /////////////////////////////////////////////////
                // Raidzilla Bug #57803:
                // If the certificate is not originally created for this
                // token, we should not revoke the certificate here.
                //
                // To figure out if this certificate is originally created
                // for this token, we check the tokenOrigin attribute.
                /////////////////////////////////////////////////
                char *origin = RA::ra_get_cert_attr_byname(e, "tokenOrigin");
                if (origin != NULL) {
                  RA::Debug("RA_Format_Processor", "Origin is %s, Current is %s", origin, cuid);
                  if (strcmp(origin, cuid) != 0) {
                    // skip this certificate, no need to do nothing
                    // We did not create this originally
                    continue;
                  }
                } else {
                  RA::Debug("RA_Format_Processor", "Origin is not present");
                }

                PR_snprintf((char *)configname, 256, "%s.%s.revokeCert", OP_PREFIX, tokenType);
                bool revokeCert = RA::GetConfigStore()->GetConfigAsBool(configname, true);
                if (revokeCert) {
                    char *attr_cn = RA::ra_get_cert_cn(e);
                    PR_snprintf((char *)configname, 256, "%s.%s.ca.conn", OP_PREFIX,
                      tokenType);
                    char *connid = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));
                    if (connid == NULL) {
                       RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process", "Failed to get connection.");
                       status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED;
                       goto loser;
                    }
                    PR_snprintf(serial, 100, "0x%s", attr_serial);
         
                    // if the certificates are revoked_on_hold, dont do 
                    // anything because the certificates may be referenced
                    // by more than one token.
                    if (strcmp(attr_status, "revoked_on_hold") == 0) {
                        RA::Debug("RA_Format_Processor", "This is revoked_on_hold certificate, skip it.");
                        if (attr_status != NULL) {
                            PL_strfree(attr_status);
                            attr_status = NULL;
                        }
                        if (attr_serial != NULL) {
                            PL_strfree(attr_serial);
                            attr_serial = NULL;
                        }
                        if (attr_cn != NULL) {
                            PL_strfree(attr_cn);
                            attr_cn = NULL;
                        }

                        continue;
                    }
                    statusNum = certEnroll->RevokeCertificate("1", serial, connid, statusString);
                    RA::ra_update_cert_status(attr_cn, "revoked");
                    if (attr_status != NULL) {
                        PL_strfree(attr_status);
                        attr_status = NULL;
                    }
                    if (attr_serial != NULL) {
                        PL_strfree(attr_serial);
                        attr_serial = NULL;
                    }
                    if (attr_cn != NULL) {
                        PL_strfree(attr_cn);
                        attr_cn = NULL;
                    }
                }
            }
            if (result != NULL)
                ldap_msgfree(result);
            if (certEnroll != NULL) 
                delete certEnroll;
        } else {
            RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process", "Failed to revoke certificates on this token.");
            status = STATUS_ERROR_REVOKE_CERTIFICATES_FAILED;
            goto loser;
        }

        rc = RA::tdb_update("", cuid, (char *)final_applet_version, keyVersion, "uninitialized", "", tokenType);

        if (rc != 0) {
            RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
	      "Failed to update the token database");
            status = STATUS_ERROR_UPDATE_TOKENDB_FAILED;
            goto loser;
        }
    } else {        
        rc = RA::tdb_update("", cuid, (char *)final_applet_version, keyVersion, "uninitialized", "", tokenType);
        if (rc != 0) {
            RA::Debug(LL_PER_PDU, "RA_Format_Processor::Process",
              "Failed to update the token database");
            status = STATUS_ERROR_UPDATE_TOKENDB_FAILED;
            goto loser;
        }
    }

    // send status update to the client
    if (extensions != NULL &&
               extensions->GetValue("statusUpdate") != NULL) {
                      StatusUpdate(session, 100 /* progress */,
                                                 "PROGRESS_DONE");
    }

    status = STATUS_NO_ERROR;
    rc = 1;

    end = PR_IntervalNow();

    sprintf(activity_msg, "applet_version=%s tokenType=%s", 
           final_applet_version, tokenType);
    RA::tdb_activity(session->GetRemoteIP(), cuid, "format", "success", activity_msg, userid, tokenType);

    /* audit log for successful enrollment */
    if (authid == NULL)
        RA::Audit("Format", "status='success' app_ver='%s' key_ver='%d' cuid='%s' msn='%s' uid='%s' time='%d msec'",
          final_applet_version,(int) finalKeyVersion, cuid, msn, userid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));
    else
        RA::Audit("Format", "status='success' app_ver='%s' key_ver='%d' cuid='%s' msn='%s' uid='%s' auth='%s' time='%d msec'",
          final_applet_version,(int) finalKeyVersion, cuid, msn, userid, authid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));

loser:

    if (keyVersion != NULL) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }

    if (ldapResult != NULL) {
        ldap_msgfree(ldapResult);
    }

    if( cplc_data != NULL ) {
        delete cplc_data;
        cplc_data = NULL;
    }
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    if( NetKeyAID != NULL ) {
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( token_status != NULL ) {
        delete token_status;
        token_status = NULL;
    }
    if( buildID != NULL ) {
        delete buildID;
        buildID = NULL;
    }
    if( appletVersion != NULL ) {
        PR_Free( (char *) appletVersion );
        appletVersion = NULL;
    }
    /*
    if( final_applet_version != NULL ) {
        PR_Free( (char *) final_applet_version );
        final_applet_version = NULL;
    }
    */
    if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( cuid );
        cuid = NULL;
    }
    if( msn != NULL ) {
        PR_Free( msn );
        msn = NULL;
    }
    if( authParams != NULL ) {
        delete authParams;
        authParams = NULL;
    }

#ifdef   MEM_PROFILING     
            MEM_dump_unfree();
#endif

    return status;
}
