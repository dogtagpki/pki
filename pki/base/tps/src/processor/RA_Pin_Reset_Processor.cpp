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

#include "engine/RA.h"
#include "main/Util.h"
#include "main/RA_Msg.h"
#include "main/RA_Session.h"
#include "channel/Secure_Channel.h"
#include "processor/RA_Processor.h"
#include "processor/RA_Pin_Reset_Processor.h"
#include "main/Memory.h"
#include "tus/tus_db.h"
#define OP_PREFIX "op.pinReset"
static const char *expected_version = NULL;

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a processor for hanlding pin reset operation.
 */
TPS_PUBLIC RA_Pin_Reset_Processor::RA_Pin_Reset_Processor()
{
}

/**
 * Destructs pin reset processor.
 */
TPS_PUBLIC RA_Pin_Reset_Processor::~RA_Pin_Reset_Processor()
{
}

/**
 * Process the current session.
 */
TPS_PUBLIC RA_Status RA_Pin_Reset_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    char **tokenOwner=NULL;
    char configname[256];
    const char *tokenType = NULL;
    char *cuid = NULL;
    const char *msn = NULL;
    PRIntervalTime start, end;
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    AuthParams *login = NULL;
    Secure_Channel *channel = NULL;
    char *new_pin = NULL;
    unsigned int minlen = 0, maxlen = 0;
    const char *applet_dir;
    bool upgrade_enc = false;
    SecurityLevel security_level = SECURE_MSG_MAC_ENC;
    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_CARDMGR_INSTANCE_AID,
		    RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_NETKEY_INSTANCE_AID,
		    RA::CFG_DEF_NETKEY_INSTANCE_AID);

    int i;
    Buffer key_data_set;
    Buffer *token_status = NULL;
    Buffer *buildID = NULL;
    char *policy = NULL; 
    char *tmp_policy = NULL; 
    const char* required_version = NULL;
    const char *appletVersion = NULL;
    const char *final_applet_version = NULL;
    const char *keyVersion = PL_strdup( "" );
    const char *userid = PL_strdup( "" );
    BYTE major_version = 0x0;
    BYTE minor_version = 0x0;
    BYTE app_major_version = 0x0;
    BYTE app_minor_version = 0x0;
    char *token_userid = NULL;

    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    Buffer token_cuid;
    Buffer token_msn;
    const char *connId = NULL;
    const char *connid = NULL;
    const char *tksid = NULL;
    const char *authid = NULL;
    AuthParams *authParams = NULL;
    start = PR_IntervalNow();
    Buffer *cplc_data = NULL;
    char activity_msg[4096];
    LDAPMessage *e = NULL;
    LDAPMessage *ldapResult = NULL;
    int maxReturns = 10;


    RA::Debug("RA_Pin_Reset_Processor::Process", "Client %s",                       session->GetRemoteIP());

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
        "RA_Pin_Reset_Processor::Process");


    SelectApplet(session, 0x04, 0x00, CardManagerAID);
    cplc_data = GetData(session);
    if (cplc_data == NULL) {
          RA::Error("RA_Pin_Reset_Processor::Process",
                        "Get Data Failed");
          status = STATUS_ERROR_SECURE_CHANNEL;
          goto loser;
    }
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "CPLC Data = ", 
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
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "Token CUID= ",
                        &token_cuid);
    cuid = Util::Buffer2String(token_cuid);

    token_msn = Buffer(cplc_data->substr(41, 4));
    RA::DebugBuffer("RA_Pin_Reset_Processor::process", "Token MSN= ",
                        &token_msn);
    msn = Util::Buffer2String(token_msn);

    /**
     * Checks if the netkey has the required applet version.
     */
    SelectApplet(session, 0x04, 0x00, NetKeyAID);
    token_status = GetStatus(session, 0x00, 0x00);
    if (token_status == NULL) {
      major_version = 0x0;
      minor_version = 0x0;
      app_major_version = 0x0;
      app_minor_version = 0x0;
    } else {
      major_version = ((BYTE*)*token_status)[0];
      minor_version = ((BYTE*)*token_status)[1];
      app_major_version = ((BYTE*)*token_status)[2];
      app_minor_version = ((BYTE*)*token_status)[3];
    }

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
              "Major=%d Minor=%d", major_version, minor_version);
    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
	      "Applet Major=%d Applet Minor=%d", app_major_version, app_minor_version);

    if (!RA::ra_is_token_present(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Not Present", cuid);
        status = STATUS_ERROR_DB;
        goto loser;
    }

     if (RA::ra_is_tus_db_entry_disabled(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Disabled", cuid);
        status = STATUS_ERROR_DISABLED_TOKEN;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "token disabled", "");
        goto loser;
     }

      if (!RA::ra_is_token_pin_resetable(cuid)) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "CUID %s Cannot Pin Reset", cuid);
        status = STATUS_ERROR_NOT_PIN_RESETABLE;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "pin not resetable", "");
        goto loser;
      }

    // retrieve CUID

    if (!GetTokenType(OP_PREFIX, major_version,
                    minor_version, cuid, msn,
                    extensions, status, tokenType)) {
		goto loser;
	}

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn",
                    OP_PREFIX, tokenType);
    tksid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (tksid == NULL) {
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "TKS Connection Parameter %s Not Found", configname);
        status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
        goto loser;
    }

    buildID = GetAppletVersion(session);
    if (buildID == NULL) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.emptyToken.enable", OP_PREFIX,
          tokenType); 
         if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
                 appletVersion = PL_strdup( "" );
         } else {
          	RA::Error("RA_Pin_Reset_Processor::Process", 
			"no applet found and applet upgrade not enabled");
                 status = STATUS_ERROR_SECURE_CHANNEL;
                RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel not established", "");
		 goto loser;
	 }
    } else {
      char * buildid =  Util::Buffer2String(*buildID);
      RA::Debug("RA_Pin_Reset_Processor", "buildid = %s", buildid);
      char version[13];
      PR_snprintf((char *) version, 13,
		  "%x.%x.%s", app_major_version, app_minor_version,
		  buildid);
      appletVersion = strdup(version);
    }

    final_applet_version = strdup(appletVersion);
    RA::Debug("RA_Pin_Reset_Processor", "final_applet_version = %s", final_applet_version);

    /**
     * Checks if we need to upgrade applet. 
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
        PR_snprintf((char *)configname, 256, "%s.%s.update.applet.requiredVersion", OP_PREFIX, tokenType);
        required_version = RA::GetConfigStore()->GetConfigAsString(configname);
	expected_version = PL_strdup(required_version);

	if (expected_version == NULL) {
             RA::Error("RA_Pin_Reset_Processor::Process", 
			"misconfiguration for upgrade");
              status = STATUS_ERROR_MISCONFIGURATION;
              goto loser;
	}
	/* Bugscape #55826: used case-insensitive check below */
        if (PL_strcasecmp(expected_version, appletVersion) != 0) {
                /* upgrade applet */
            PR_snprintf((char *)configname, 256, "%s.%s.update.applet.directory", OP_PREFIX, tokenType);
            applet_dir = RA::GetConfigStore()->GetConfigAsString(configname);
            if (applet_dir == NULL) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet",
                                "Failed to get %s", applet_dir);
                goto loser;
            }
            PR_snprintf((char *)configname, 256, "%s.%s.update.applet.encryption", OP_PREFIX, tokenType);
            upgrade_enc = RA::GetConfigStore()->GetConfigAsBool(configname, true);
            if (!upgrade_enc)
              security_level = SECURE_MSG_MAC;
            PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
            connid = RA::GetConfigStore()->GetConfigAsString(configname);
            int upgrade_rc = UpgradeApplet(session, OP_PREFIX, (char*)tokenType, major_version, minor_version, expected_version, applet_dir, security_level, connid, extensions, 30, 70);
	    if (upgrade_rc != 1) {
               RA::Error("RA_Pin_Reset_Processor::Process", 
			"upgrade failure");
              status = STATUS_ERROR_UPGRADE_APPLET;
              RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "applet upgrade error", "");
              /**
               * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
               */
              SelectApplet(session, 0x04, 0x00, NetKeyAID);
              goto loser;
	    }
            RA::Audit("Pin Reset", "op='applet_upgrade' app_ver='%s' new_app_ver='%s'", 
			    appletVersion, expected_version);
	    final_applet_version = expected_version;
        }
    }

    /**
     * Checks if the netkey has the required key version.
     */
    PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
      PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
      int requiredVersion = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
      PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
      connId = RA::GetConfigStore()->GetConfigAsString(configname);
      if( channel != NULL ) {
          delete channel;
          channel = NULL;
      }
      channel = SetupSecureChannel(session, requiredVersion, 
                  0x00  /* default key index */, connId);
      if (channel == NULL) {

        /* if version 0x02 key not found, create them */
        SelectApplet(session, 0x04, 0x00, CardManagerAID);
        channel = SetupSecureChannel(session,
                  0x00,  /* default key version */
                  0x00  /* default key index */, connId);

        if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"setup secure channel failure");
            status = STATUS_ERROR_SECURE_CHANNEL;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel not established", "");
            goto loser;
	}

        rc = channel->ExternalAuthenticate();
        if (rc != 1) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"External authentication in secure channel failed");
            status = STATUS_ERROR_EXTERNAL_AUTH;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "external authentication error", "");
            goto loser;
        } 

        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        int v = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);
        Buffer curKeyInfo = channel->GetKeyInfoData();
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
            RA::Error("RA_Pin_Reset_Processor::Process",
                        "failed to create new key set");
            status = STATUS_ERROR_CREATE_CARDMGR;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "create key set error", "");
            goto loser;
        }


	 BYTE curVersion = ((BYTE*)curKeyInfo)[0];
         BYTE curIndex = ((BYTE*)curKeyInfo)[1];
         rc = channel->PutKeys(session,
                  curVersion,
                  curIndex,
                  &key_data_set);

        RA::Audit("Pin Reset", "op='key_change_over' app_ver='%s' cuid='%s' old_key_ver='%02x01' new_key_ver='%02x01'", final_applet_version, cuid, curVersion, ((BYTE*)newVersion)[0]);


         SelectApplet(session, 0x04, 0x00, NetKeyAID);
        PR_snprintf((char *)configname, 256, "%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, tokenType);
        if( channel != NULL ) {
            delete channel;
            channel = NULL;
        }

        PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
        connId = RA::GetConfigStore()->GetConfigAsString(configname);
         channel = SetupSecureChannel(session, 
                  RA::GetConfigStore()->GetConfigAsInt(configname, 0x00),
                  0x00  /* default key index */, connId);
         if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"setup secure channel failure");
            status = STATUS_ERROR_CREATE_CARDMGR;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel not established", "");
            goto loser;
         }
      }
    } else {
      PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
      connId = RA::GetConfigStore()->GetConfigAsString(configname);
      if( channel != NULL ) {
          delete channel;
          channel = NULL;
      }
      channel = SetupSecureChannel(session,
                  0x00,
                  0x00  /* default key index */, connId);
    }

    /* we should have a good channel here */
    if (channel == NULL) {
            RA::Error("RA_Pin_Reset_Processor::Process", 
			"no channel creation failure");
            status = STATUS_ERROR_CREATE_CARDMGR;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel not established", "");
            goto loser;
    }

    if (channel != NULL) {
	if( keyVersion != NULL ) {
		PR_Free( (char *) keyVersion );
		keyVersion = NULL;
	}
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
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
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"login not provided");
        status = STATUS_ERROR_LOGIN;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "login not found", "");
        goto loser;
      }
      if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
      }
      userid = PL_strdup( login->GetUID() );
    }

    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 30 /* progress */,
                        "PROGRESS_START_AUTHENTICATION");
    }

    PR_snprintf(configname, 256, "cn=%s", cuid);
    rc = RA::ra_find_tus_token_entries(configname, maxReturns, &ldapResult, 0);

    if (rc == 0) {
        for (e = RA::ra_get_first_entry(ldapResult); e != NULL;
          e = RA::ra_get_next_entry(e)) {
            tokenOwner = RA::ra_get_attribute_values(e, "tokenUserID");
            if (tokenOwner[0] != NULL && strlen(tokenOwner[0]) > 0 &&
                strcmp(userid, tokenOwner[0]) != 0) {
                status = STATUS_ERROR_NOT_TOKEN_OWNER;
                goto loser;
            }
        }
    } else {
        RA::Error("RA_Pin_Reset_Processor::Process", "Error in ldap connection with token database.");
        status = STATUS_ERROR_LDAP_CONN;
        goto loser;
    }

    PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, false)) {
        if (login == NULL) {
                RA::Error("RA_Pin_Reset_Processor::Process", "Login Request Disabled. Authentication failed.");
                status = STATUS_ERROR_LOGIN;
                goto loser;
        }


        PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, tokenType);
        authid = RA::GetConfigStore()->GetConfigAsString(configname);
        if (authid == NULL) {
                status = STATUS_ERROR_LOGIN;
            goto loser;
	}
        AuthenticationEntry *auth = RA::GetAuth(authid);
   
        if(auth == NULL) 
        {
            RA::Error("RA_Pin_Reset_Processor::Process", "Authentication manager is NULL . Authentication failed.");
            status = STATUS_ERROR_LOGIN;
            goto loser;
        }
 
        char *type = auth->GetType();
        if (type == NULL) {
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "authentication is missing param type", "");
            goto loser;
        }
        if (strcmp(type, "LDAP_Authentication") == 0) {
            RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
                    "LDAP_Authentication is invoked.");
            int passwd_retries = auth->GetAuthentication()->GetNumOfRetries();
            int retries = 0;
            authParams = new AuthParams();
            authParams->SetUID(login->GetUID());
            authParams->SetPassword(login->GetPassword());
            rc = auth->GetAuthentication()->Authenticate(authParams);

            RA::Debug("RA_Pin_Reset_Processor::Process",
              "Authenticate returns: %d", rc);

            while ((rc == -2 || rc == -3) && (retries < passwd_retries)) {
                login = RequestLogin(session, 0 /* invalid_pw */, 0 /* blocked */);
                if (login == NULL) {
                    RA::Error("RA_Pin_Reset_Processor::Process", "Login Request Disabled. Authentication failed.");
                    status = STATUS_ERROR_LOGIN;
                    goto loser;
                }
                retries++;
                authParams->SetUID(login->GetUID());
                authParams->SetPassword(login->GetPassword());
                rc = auth->GetAuthentication()->Authenticate(authParams);
            }

            if (rc == -1) {
                RA::Error("RA_Pin_Reset_Processor::Process", "Authentication failed.");
                status = STATUS_ERROR_LDAP_CONN;
                RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", "Authentication status = %d", status);
                goto loser; 
            }

            if (rc == -2 || rc == -3) {
                RA::Error("RA_Pin_Reset_Processor::Process", "Authentication failed.");
                status = STATUS_ERROR_LOGIN;
                RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", "Authentication status = %d", status);
                goto loser; 
            }

            RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", "Authentication successful.");
        } else {
            RA::Error("RA_Pin_Reset_Processor::Process", "No Authentication type was found.");
            status = STATUS_ERROR_LOGIN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "authentication error", "");
            goto loser;
        }
    } else {
        RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "Authentication has been disabled.");
    }

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "SetupSecureChannel");

#if 0
    if (RA::GetConfigStore()->GetConfigAsBool("tus.enable", 0)) {
        if (IsTokenDisabledByTus(channel)) {
           status = STATUS_ERROR_TOKEN_DISABLED;
           goto loser;
        }
    }
#endif

    /* check if the user owns the token */
    token_userid = RA::ra_get_token_userid(cuid);
    if (token_userid == NULL) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "No user owns the token '%s'", cuid);
        status = STATUS_ERROR_TOKEN_DISABLED;
        goto loser;
    } else {
      if (strcmp(token_userid, userid) != 0) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "User does not own the token '%s'", cuid);
        status = STATUS_ERROR_TOKEN_DISABLED;
        goto loser;
      }
    }

    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "ExternalAuthenticate");
    rc = channel->ExternalAuthenticate();
    if (rc == -1) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"External Authenticate failed.");
        status = STATUS_ERROR_CREATE_CARDMGR;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "external authentication error", "");
        goto loser;
    }
    RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor::Process", 
          "RequestNewPin");
    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.minLen", OP_PREFIX, tokenType);
    minlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 4);
    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.maxLen", OP_PREFIX, tokenType);
    maxlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 10);
    new_pin = RequestNewPin(session, minlen, maxlen);
    if (new_pin == NULL) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"Set Pin failed.");
        status = STATUS_ERROR_MAC_RESET_PIN_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "request new pin error", "");
        goto loser;
    }

    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 70 /* progress */,
                        "PROGRESS_PIN_RESET");
    }

    rc = channel->ResetPin(0x0, new_pin);
    if (rc == -1) {
        status = STATUS_ERROR_MAC_RESET_PIN_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "ereset pin error", "");
        goto loser;
    }

    rc = channel->Close();
    if (rc == -1) {
        RA::Error("RA_Pin_Reset_Processor::Process", 
			"Failed to close channel");
        status = STATUS_ERROR_CONNECTION;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "pin reset", "failure", "secure channel close error", "");
        goto loser;
    }

    if (extensions != NULL &&
           extensions->GetValue("statusUpdate") != NULL) {
           StatusUpdate(session, 100 /* progress */,
                        "PROGRESS_DONE");
    }

    end = PR_IntervalNow();

    rc = 1;

    if (RA::ra_is_token_present(cuid)) {
	    /* 
	     * we want to have a tus policy to change PIN_RESET=YES 
	     * parameter to PIN_RESET=NO
	     */
      if (RA::ra_is_token_pin_resetable(cuid)) {
	policy = RA::ra_get_token_policy(cuid);
        RA::Error("RA_Pin_Reset_Processor::Process",
                        "Policy %s is %s", cuid, policy);
	tmp_policy = PL_strstr(policy, "PIN_RESET=YES");
	if (tmp_policy != NULL) {
	  tmp_policy[10] = 'N';
	  tmp_policy[11] = 'O';
	  for (i = 12; tmp_policy[i] != '\0'; i++)
	    tmp_policy[i] = tmp_policy[i+1];
	  RA::ra_update_token_policy(cuid, policy);
	}
      }
    }

    sprintf(activity_msg, "applet_version=%s tokenType=%s",
           (char *)final_applet_version, tokenType);
    RA::tdb_activity(session->GetRemoteIP(), (char *)cuid, "pin reset", "success", activity_msg, userid);

    /* audit log for successful pin reset */
    if (authid == NULL)
        RA::Audit("Pin Reset", "status='success' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' uid='%s' time='%d msec'",
          final_applet_version, keyVersion, cuid, msn, userid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));
    else 
        RA::Audit("Pin Reset", "status='success' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' uid='%s' auth='%s' time='%d msec'",
          final_applet_version, keyVersion, cuid, msn, userid, authid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));

loser:
    if (channel == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Pin_Reset_Processor: Failed to create secure channel.", "");
        if (login == NULL) {
            RA::Audit("Pin Reset", "status='error' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' note='failed to login'", final_applet_version, keyVersion, cuid, msn);
	} else { 
            RA::Audit("Pin Reset", "status='error' app_ver='%s' key_ver='%s' cuid='%s' msn='%s'  uid='%s' note='failed to create secure channel'", final_applet_version, keyVersion, cuid, msn, userid);  
        } 
    } else if (rc != 1 && status == STATUS_ERROR_LOGIN) {
        if (login == NULL) {
            RA::Audit("Pin Reset", "status='error' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' note='login failure'", final_applet_version, keyVersion, cuid, msn);
	} else {
            RA::Audit("Pin Reset", "status='error' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' uid='%s' note='authentication failure'", 
                final_applet_version, keyVersion, cuid, msn, userid);
        } 
    }
    if( token_status != NULL ) {
        delete token_status;
        token_status = NULL;
    }
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    if( NetKeyAID != NULL ) { 
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( login != NULL ) {
        delete login;
        login = NULL;
    }
    if( new_pin != NULL ) {
        PL_strfree( new_pin );
        new_pin = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( (char *) cuid );
        cuid = NULL;
    }
    if( msn != NULL ) {
        PR_Free( (char *) msn );
        msn = NULL;
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
    if( keyVersion != NULL ) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }
    if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
    }
    if( authParams != NULL ) {
        delete authParams;
        authParams = NULL;
    }
    if( cplc_data != NULL ) {
        delete cplc_data;
        cplc_data = NULL;
    }

    if (tokenOwner != NULL) {
        ldap_value_free(tokenOwner);
        tokenOwner = NULL;
    }

    if (ldapResult != NULL) {
        ldap_msgfree(ldapResult);
        ldapResult = NULL;
    }

#ifdef   MEM_PROFILING     
         MEM_dump_unfree();
#endif

    return status;
} /* Process */
