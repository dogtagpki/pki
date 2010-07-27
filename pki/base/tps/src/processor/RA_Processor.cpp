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
#include "plstr.h"
#include "engine/RA.h"
#include "main/Buffer.h"
#include "main/Base.h"
#include "main/Util.h"
#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Login.h"
#include "main/SecureId.h"
#include "main/Util.h"
#include "httpClient/httpc/http.h"
#include "httpClient/httpc/request.h"
#include "httpClient/httpc/response.h"
#include "httpClient/httpc/engine.h"
#include "processor/RA_Processor.h"
#include "cms/HttpConnection.h"
#include "msg/RA_Status_Update_Request_Msg.h"
#include "msg/RA_Status_Update_Response_Msg.h"
#include "msg/RA_Login_Request_Msg.h"
#include "msg/RA_Login_Response_Msg.h"
#include "msg/RA_Extended_Login_Request_Msg.h"
#include "msg/RA_Extended_Login_Response_Msg.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "msg/RA_ASQ_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/Get_Version_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Get_Status_APDU.h"
#include "apdu/Get_Data_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/List_Objects_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Select_APDU.h"
#include "apdu/APDU_Response.h"
#include "channel/Secure_Channel.h"
#include "main/Memory.h"

#if 0
#ifdef __cplusplus
extern "C"
{
#endif
#include "tus/tus_db.h"
#ifdef __cplusplus
}
#endif
#endif

/**
 * Constructs a base processor.
 */
RA_Processor::RA_Processor ()
{
}


/**
 * Destructs processor.
 */
RA_Processor::~RA_Processor ()
{
}

AuthenticationEntry *RA_Processor::GetAuthenticationEntry(
            const char *prefix, const char * a_configname, const char *a_tokenType)
{
    AuthenticationEntry *auth = NULL;
                                                                                
    if (!RA::GetConfigStore()->GetConfigAsBool(a_configname, false))
            return NULL;
                                                                                
        RA::Debug("RA_Enroll_Processor::AuthenticateUser",
                "Authentication enabled");
    char configname[256];
    PR_snprintf((char *)configname, 256, "%s.%s.auth.id", prefix, a_tokenType);
    const char *authid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (authid == NULL) {
        goto loser;
    }
    auth = RA::GetAuth(authid);
        return auth;
loser:
    return NULL;
}


void RA_Processor::StatusUpdate(RA_Session *a_session,  
		NameValueSet *a_extensions,
    int a_status, const char *a_info)
{
    if (a_extensions != NULL) {
		if (a_extensions->GetValue("statusUpdate") != NULL) {
        	StatusUpdate(a_session, a_status, a_info);
		}
    }
}

void RA_Processor::StatusUpdate(RA_Session *session,  
    int status, const char *info)
{
    RA_Status_Update_Request_Msg *status_update_request_msg = NULL;
    RA_Status_Update_Response_Msg *status_update_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::StatusUpdate",
        "RA_Processor::StatusUpdate");

    status_update_request_msg = new RA_Status_Update_Request_Msg(
        status, info);
    session->WriteMsg(status_update_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::StatusUpdate",
        "Sent status_update_msg");

    status_update_response_msg = (RA_Status_Update_Response_Msg *)
        session->ReadMsg();
    if (status_update_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::StatusUpdate",
            "No Status Update Response Msg Received");
        goto loser;
    }
    if (status_update_response_msg->GetType() != MSG_STATUS_UPDATE_RESPONSE) {
            RA::Error("Secure_Channel::StatusUpdate",
            "Invalid Msg Type");
            goto loser;
    }

loser:
    if( status_update_request_msg != NULL ) {
        delete status_update_request_msg;
        status_update_request_msg = NULL;
    }
    if( status_update_response_msg != NULL ) {
        delete status_update_response_msg;
        status_update_response_msg = NULL;
    }

} /* StatusUpdate */

/**
 * Requests login ID and password from user.
 */
AuthParams *RA_Processor::RequestExtendedLogin(RA_Session *session,  
    int invalid_pw, int blocked,
    char **parameters, int len, char *title, char *description)
{
    RA_Extended_Login_Request_Msg *login_request_msg = NULL;
    RA_Extended_Login_Response_Msg *login_response_msg = NULL;
    AuthParams *login = NULL;
    AuthParams *c = NULL;
    int i = 0;

    RA::Debug(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
        "RA_Processor::RequestExtendedLogin %s %s", 
        title, description);

    login_request_msg = new RA_Extended_Login_Request_Msg(
        invalid_pw, blocked, parameters, len, title, description);
    session->WriteMsg(login_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
        "Sent login_request_msg");

    login_response_msg = (RA_Extended_Login_Response_Msg *)
        session->ReadMsg();
    if (login_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::RequestExtendedLogin",
            "No Extended Login Response Msg Received");
        goto loser;
    }
    if (login_response_msg->GetType() != MSG_EXTENDED_LOGIN_RESPONSE) {
            RA::Error("Secure_Channel::Login_Request",
            "Invalid Msg Type");
            goto loser;
    }

    login = new AuthParams();
    c = login_response_msg->GetAuthParams();
    for (i = 0; i < c->Size(); i++) {
      login->Add(c->GetNameAt(i), c->GetValue(c->GetNameAt(i)));
    }

loser:
    if( login_request_msg != NULL ) {
        delete login_request_msg;
        login_request_msg = NULL;
    }
    if( login_response_msg != NULL ) {
        delete login_response_msg;
        login_response_msg = NULL;
    }

    return login;
} /* RequestExtendedLogin */

/**
 * Requests login ID and password from user.
 */
AuthParams *RA_Processor::RequestLogin(RA_Session *session,  
    int invalid_pw, int blocked)
{
    RA_Login_Request_Msg *login_request_msg = NULL;
    RA_Login_Response_Msg *login_response_msg = NULL;
    AuthParams *login = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::Login_Request",
        "RA_Processor::Login_Request");

    login_request_msg = new RA_Login_Request_Msg(
        invalid_pw, blocked);
    session->WriteMsg(login_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::Login_Request",
        "Sent login_request_msg");

    login_response_msg = (RA_Login_Response_Msg *)
        session->ReadMsg();
    if (login_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::Login_Request",
            "No Login Response Msg Received");
        goto loser;
    }
    if (login_response_msg->GetType() != MSG_LOGIN_RESPONSE) {
            RA::Error("Secure_Channel::Login_Request",
            "Invalid Msg Type");
            goto loser;
    }
    login = new AuthParams();
    login->Add("UID", login_response_msg->GetUID());
    login->Add("PASSWORD", login_response_msg->GetPassword());

loser:
    if( login_request_msg != NULL ) {
        delete login_request_msg;
        login_request_msg = NULL;
    }
    if( login_response_msg != NULL ) {
        delete login_response_msg;
        login_response_msg = NULL;
    }

    return login;
} /* RequestLogin */

/**
 * Upgrade the applet to the current session with the new version.
 */
int RA_Processor::UpgradeApplet(RA_Session *session, char *prefix, char *tokenType, BYTE major_version, BYTE minor_version, const char *new_version, const char *applet_dir, SecurityLevel security_level, const char *connid,
		NameValueSet *extensions,
		int start_progress,
		int end_progress, 
                char **key_version)
{
        Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_INSTANCE_AID,
		        RA::CFG_DEF_NETKEY_INSTANCE_AID);
        Buffer *OldAAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_OLD_INSTANCE_AID,
		        RA::CFG_DEF_NETKEY_OLD_INSTANCE_AID);
        Buffer *OldPAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_OLD_FILE_AID,
		        RA::CFG_DEF_NETKEY_OLD_FILE_AID);
        Buffer *NetKeyPAID = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_NETKEY_FILE_AID,
		        RA::CFG_DEF_NETKEY_FILE_AID);
        Buffer *PIN = RA::GetConfigStore()->GetConfigAsBuffer(
			RA::CFG_APPLET_SO_PIN,
		        RA::CFG_DEF_APPLET_SO_PIN);
        Buffer empty;
	PRFileDesc *f = NULL;
	char path[4096];
	char configname[4096];
	PRFileInfo info;
	PRStatus status;
	int rc = 0;
        Secure_Channel *channel = NULL;
	int size_to_send = 0;
	char *dataf = NULL;
	int block_size;
	BYTE refControl;
	int count;
	Buffer programFile;
        Buffer tag;
        Buffer length;
        Buffer tbsProgramFile;
        unsigned int totalLen;
	int num_loops;
	float progress_block_size;
	int x_blocksize;
	int instance_size;
	int defKeyVer;
	int defKeyIndex;
	char *ext;

	if (applet_dir == NULL) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
				"Failed to get upgrade.directory");
		goto loser;		
	}
	sprintf(configname, "general.applet_ext");
	ext = (char*)RA::GetConfigStore()->GetConfigAsString(configname, "ijc");
	sprintf(path, "%s/%s.%s", applet_dir, new_version, ext);
	RA::Debug("RA_Processor::UpgradeApplet", "path = %s", path);
	status = PR_GetFileInfo(path, &info);
	if (status != PR_SUCCESS) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
				"Failed to get file info");
		goto loser;		
	}
	f = PR_Open(path, PR_RDONLY, 400);
	if (f == NULL) {
                RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
			"Failed to open '%s'", path);
		goto loser;		
	}
	dataf = (char *)malloc(info.size);
	PR_Read(f, dataf, info.size);
    if( f != NULL ) {
	    PR_Close( f );
        f = NULL;
    }

	/* Select Applet - Select Card manager */
	SelectCardManager(session, prefix, tokenType);

    PR_snprintf((char *)configname, 256,"channel.blockSize");
    x_blocksize = RA::GetConfigStore()->GetConfigAsInt(configname, 0xf8);
    PR_snprintf((char *)configname, 256,"channel.instanceSize");
    instance_size = RA::GetConfigStore()->GetConfigAsInt(configname, 18000);
    PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
    defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
    PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
    defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
	channel = SetupSecureChannel(session, defKeyVer, defKeyIndex, security_level, connid);
	if (channel == NULL) {
             RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "channel creation failure");
	     goto loser;
	}

        // get keyVersion
        if (channel != NULL) {
            *key_version = Util::Buffer2String(channel->GetKeyInfoData());
        }

	if (channel->ExternalAuthenticate() == -1) {
             RA::Error(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "failed to external authenticate during upgrade");
	     goto loser;
	}

	/* Delete File - Delete 627601ff000000 (CoolKey Instance) */
        rc = channel->DeleteFileX(session, NetKeyAID);
	if (rc != 1) {
	     /* it is ok to fail to delete file */
             RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", NetKeyAID);
	}

	if (RA::GetConfigStore()->GetConfigAsBool(RA::CFG_APPLET_DELETE_NETKEY_OLD, true)) {
	    /* Delete File - Delete a00000000101 */
            rc = channel->DeleteFileX(session, OldAAID);
	    if (rc != 1) {
	       /* it is ok to fail to delete file */
               RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", OldAAID);
	    }
	    /* Delete File - Delete a000000001 */
            rc = channel->DeleteFileX(session, OldPAID);
	    if (rc != 1) {
               RA::DebugBuffer(LL_PER_PDU, "RA_Processor::UpgradeApplet", 
		  "Warning: failed to delete file", OldPAID);
	    }
	}

	/* Delete File - Delete 627601ff0000 */
        channel->DeleteFileX(session, NetKeyPAID);

	/* Install Applet - Install applet instance */
        channel->InstallLoad(session, 
			*NetKeyPAID,
			empty,
			info.size);

	/* Multiple Load Program File - Load 627601ff0000 */
	programFile = Buffer ((BYTE *)dataf, info.size);
	if( dataf != NULL ) {
        free( dataf );
        dataf = NULL;
	}
        tag = Buffer(1, 0xC4);
        tbsProgramFile = tag + length + programFile;
        totalLen = tbsProgramFile.size();
        if( programFile.size() < 128 ) {
            length = Buffer(1, programFile.size());
        } else if( programFile.size() <= 255 ) {
            length = Buffer(2, 0);
            ((BYTE*)length)[0] = 0x81;
	    ((BYTE*)length)[1] = programFile.size();
	} else {
            length = Buffer(3, 0);
            ((BYTE*)length)[0] = 0x82;
            ((BYTE*)length)[1] = (programFile.size() >> 8) & 0xff;
            ((BYTE*)length)[2] = programFile.size() & 0xff;
        }
        tbsProgramFile = tag + length + programFile;
        totalLen = tbsProgramFile.size();

	size_to_send = totalLen;
	if (security_level == SECURE_MSG_MAC_ENC) {
	  // need leave room for possible encryption padding
	  block_size = x_blocksize - 0x10;
	} else {
	  block_size = x_blocksize - 8;
	}

	// rough number is good enough
	num_loops = size_to_send / block_size;
	progress_block_size = (float) (end_progress - start_progress) / num_loops;

	count = 0;
	refControl = 0x00; // intermediate block
	do {
		if (size_to_send < block_size) {
			block_size = size_to_send;
			// last block		
			refControl = 0x80;
		}
		if (size_to_send - block_size == 0) {
			// last block		
			refControl = 0x80;
		}
		Buffer d = tbsProgramFile.substr(totalLen - size_to_send, block_size);
                channel->LoadFile(session, (BYTE)refControl, (BYTE)count,  &d);

		size_to_send -= block_size;

		// send status update to the client
		if (extensions != NULL && 
		    extensions->GetValue("statusUpdate") != NULL) {
		  StatusUpdate(session, 
			start_progress + (count * progress_block_size) /* progress */, 
			"PROGRESS_APPLET_BLOCK");
		}
		count++;
	} while (size_to_send > 0);


	/* Install Applet - Install applet instance */
        channel->InstallApplet(session, 
			*NetKeyPAID,
			*NetKeyAID,
			0 /* appPrivileges */,
			instance_size /* instanceSize */);

	/* Select File - Select 627601ff000000 */
        SelectApplet(session, 0x04, 0x00, NetKeyAID);

	rc = 1;
loser:
    if( NetKeyAID != NULL ) {
        delete NetKeyAID;
        NetKeyAID = NULL;
    }
    if( OldAAID != NULL ) {
        delete OldAAID;
        OldAAID = NULL;
    }
    if( OldPAID != NULL ) {
        delete OldPAID;
        OldPAID = NULL;
    }
    if( NetKeyPAID != NULL ) {
        delete NetKeyPAID;
        NetKeyPAID = NULL;
    }
    if( PIN != NULL ) {
        delete PIN;
        PIN = NULL;
    }
    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }
    if( dataf != NULL ) {
        free( dataf );
        dataf = NULL;
    }

	return rc;
}

char *RA_Processor::MapPattern(NameValueSet *nv, char *pattern)
{
        int i=0,x=0,j=0,z=0;
        unsigned int q = 0;
        char token[4096];
        char result[4096];
	char *value;

	if (pattern == NULL)
		return NULL;
        i = strlen(pattern);
        for (x = 0; x < i; x++) {
                if (pattern[x] == '$') {
                  if (pattern[x+1] == '$') {
                        result[z] = pattern[x];
			z++;
                        x++;
                  } else {
                          x++;
                          j = 0;
                          while (pattern[x] != '$') {
                                  token[j] = pattern[x];
                                  j++;
                                  x++;
                          }
                          token[j] = '\0';
			  value = nv->GetValue(token);
			  if (value != NULL) {
                             for (q = 0; q < strlen(value); q++) {
                                 result[z] = value[q];
				 z++;
			     }

			  }
                  }
                } else {
                        result[z] = pattern[x];
			z++;
                }
        }
	result[z] = '\0';

	return PL_strdup(result);
}

int RA_Processor::FormatMuscleApplet(RA_Session *session,
        unsigned short memSize,
        Buffer &PIN0, BYTE pin0Tries,
        Buffer &unblockPIN0, BYTE unblock0Tries,
        Buffer &PIN1, BYTE pin1Tries,
        Buffer &unblockPIN1, BYTE unblock1Tries,
        unsigned short objCreationPermissions,
        unsigned short keyCreationPermissions,
        unsigned short pinCreationPermissions)
{   
    int rc = 0;
    APDU_Response *format_response = NULL;
    RA_Token_PDU_Request_Msg *format_request_msg = NULL;
    RA_Token_PDU_Response_Msg *format_response_msg = NULL;
    Format_Muscle_Applet_APDU *format_apdu = NULL;
    // Buffer *mac = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::FormatMuscle",
        "RA_Processor::FormatMuscle");

    format_apdu = new Format_Muscle_Applet_APDU(memSize, PIN0, pin0Tries,
                                unblockPIN0, unblock0Tries,
                                PIN1, pin1Tries,
                                unblockPIN1, unblock1Tries,
                                objCreationPermissions,
                                keyCreationPermissions,
                                pinCreationPermissions);
    format_request_msg =
        new RA_Token_PDU_Request_Msg(format_apdu);
    session->WriteMsg(format_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::FormatMuscle",
        "Sent format_request_msg");

    format_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (format_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (format_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle", 
		"Invalid Message Type");
           goto loser;
    }
    format_response = format_response_msg->GetResponse();
    if (!(format_response->GetSW1() == 0x90 && 
        format_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::FormatMuscle",
            "Bad Response");
	goto loser;
    }
    rc = 1;

loser:
    if( format_request_msg != NULL ) {
        delete format_request_msg;
        format_request_msg = NULL;
    }
    if( format_response_msg != NULL ) {
        delete format_response_msg;
        format_response_msg = NULL;
    }

    return rc;
}

/**
 * Determine the Token Type. The user can set up mapping rules in the 
 * config file which allow different operations depending on the
 * CUID, applet version, ATR, etc.
 */
bool RA_Processor::GetTokenType(const char *prefix, int major_version, int minor_version, const char *cuid, const char *msn, NameValueSet *extensions, 
	RA_Status &o_status /* out */, const char *&o_tokenType /* out */)
{
	const char *e_tokenATR = NULL;
	const char *tokenATR = NULL;
	const char *e_tokenType = NULL;
	const char *tokenType = NULL;
	const char *tokenCUIDStart = NULL;
	const char *tokenCUIDEnd = NULL;
	const char *targetTokenType = NULL;
	const char *majorVersion = NULL;
	const char *minorVersion = NULL;
	const char *order = NULL;
	char *order_x = NULL;
	const char *mappingId = NULL;
	char configname[256];
	int start_pos = 0, done = 0;
	unsigned int end_pos = 0;
	const char *cuid_x = NULL;

	cuid_x = cuid;

	sprintf(configname, "%s.mapping.order", prefix);
	order = RA::GetConfigStore()->GetConfigAsString(configname);
	if (order == NULL) {
		RA::Error("RA_Processor::GetTokenType", "Token type is not found");
    	o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
				"cannot find config ", configname);
		return false; /* no mapping found */
	}

	RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
			"Starting:");
	order_x = PL_strdup(order);

	start_pos = 0;
	end_pos = 0;
	done = 0;
	while (1) 
	{
		if (done) {
			break;
		}
		end_pos = start_pos;
		while ((end_pos < strlen(order)) && (order_x[end_pos] != ',')) {
			end_pos++;
		}
		if (end_pos < strlen(order)) {
			order_x[end_pos] = '\0';
			done = 0;
		} else {
			done = 1;
		}
		mappingId = &order_x[start_pos];
		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
				"mappingId='%s'", mappingId);

		start_pos = end_pos + 1;

		sprintf(configname, "%s.mapping.%s.target.tokenType", prefix, 
				mappingId);
		targetTokenType = RA::GetConfigStore()->GetConfigAsString(configname);


		if (targetTokenType == NULL) {
			break;
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenType", prefix, 
				mappingId);
		tokenType = RA::GetConfigStore()->GetConfigAsString(configname);

		RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
				"tokenType: %s",tokenType);

		if (tokenType != NULL && strlen(tokenType) > 0) {
			if (extensions == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			e_tokenType = extensions->GetValue("tokenType");
			if (e_tokenType == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			if (strcmp(tokenType, e_tokenType) != 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenATR", prefix, 
				mappingId);
		tokenATR = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenATR != NULL && strlen(tokenATR) > 0) {
			if (extensions == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			e_tokenATR = extensions->GetValue("tokenATR");
			if (e_tokenATR == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			if (strcmp(tokenATR, e_tokenATR) != 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenCUID.start", prefix, 
				mappingId);
		tokenCUIDStart = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenCUIDStart != NULL && strlen(tokenCUIDStart) > 0) {
			if (cuid_x == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
					"cuid_x=%s tokenCUIDStart=%s %d", cuid_x, tokenCUIDStart, 
					PL_strcasecmp(cuid_x, tokenCUIDStart));

			if(strlen(tokenCUIDStart) != 20)
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDStart: %s",tokenCUIDStart);
				continue;
			}

			char *pend = NULL;
			strtol((const char *) tokenCUIDStart, &pend, 16);

			if(*pend != '\0')
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDStart: %s",tokenCUIDStart);

				continue;
			}

			if (PL_strcasecmp(cuid_x, tokenCUIDStart) < 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.tokenCUID.end", prefix, 
				mappingId);
		tokenCUIDEnd = RA::GetConfigStore()->GetConfigAsString(configname);
		if (tokenCUIDEnd != NULL && strlen(tokenCUIDEnd) > 0) {
			if (cuid_x == NULL) {
				continue; /* mapping not matched, next mapping */
			}
			RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType", 
					"cuid_x=%s tokenCUIDEnd=%s %d", cuid_x, tokenCUIDEnd, 
					PL_strcasecmp(cuid_x, tokenCUIDEnd));

			if(strlen(tokenCUIDEnd) != 20)
			{
				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDEnd: %s",tokenCUIDEnd);
				continue;
			}

			char *pend = NULL;
			strtol((const char *) tokenCUIDEnd, &pend, 16);

			if(*pend != '\0')
			{

				RA::Debug(LL_PER_PDU, "RA_Processor::GetTokenType",
						"Invalid tokenCUIDEnd: %s",tokenCUIDEnd);

				continue;
			}

			if (PL_strcasecmp(cuid_x, tokenCUIDEnd) > 0) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.appletMajorVersion", 
				prefix, mappingId);
		majorVersion = RA::GetConfigStore()->GetConfigAsString(configname);
		if (majorVersion != NULL && strlen(majorVersion) > 0) {
			if (major_version != atoi(majorVersion)) {
				continue; /* mapping not matched, next mapping */
			}
		}
		sprintf(configname, "%s.mapping.%s.filter.appletMinorVersion", 
				prefix, mappingId);
		minorVersion = RA::GetConfigStore()->GetConfigAsString(configname);
		if (minorVersion != NULL && strlen(minorVersion) > 0) {
			if (minor_version != atoi(minorVersion)) {
				continue; /* mapping not matched, next mapping */
			}
		}

		if( order_x != NULL ) {
			PL_strfree( order_x );
			order_x = NULL;
		}
	    RA::Debug("RA_Processor::GetTokenType",
                        "Selected Token type is '%s'", targetTokenType);
		o_tokenType = targetTokenType;
		return true;
	}


	if( order_x != NULL ) {
		PL_strfree( order_x );
		order_x = NULL;
	}
	RA::Error("RA_Processor::GetTokenType", "Token type is not found");
    o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
	
	return false;
}

int RA_Processor::SelectCardManager(RA_Session *session, char *prefix, char *tokenType)
{
    char configname[256];
    int rc;
    PR_snprintf((char *)configname, 256, "%s.%s.cardmgr_instance", prefix, tokenType);
    const char *cardmgr_instance = 
          RA::GetConfigStore()->GetConfigAsString(configname);
    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
           cardmgr_instance, RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    rc = SelectApplet(session, 0x04, 0x00, CardManagerAID);
    if( CardManagerAID != NULL ) {
        delete CardManagerAID;
        CardManagerAID = NULL;
    }
    return rc;
}

/**
 * GetData  
 */
Buffer *RA_Processor::GetData(RA_Session *session)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *get_data_response = NULL;
    RA_Token_PDU_Request_Msg *get_data_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_data_response_msg = NULL;
    Get_Data_APDU *get_data_apdu = NULL;
    Buffer get_status_data;

    get_data_apdu =
        new Get_Data_APDU();
    get_data_request_msg =
        new RA_Token_PDU_Request_Msg(get_data_apdu);
    session->WriteMsg(get_data_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetData",
        "Sent get_data_request_msg");

    get_data_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_data_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetData",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_data_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetData", 
		"Invalid Message Type");
           goto loser;
    }
    get_data_response =
        get_data_response_msg->GetResponse();
    if (get_data_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetData", 
		"No Response From Token");
           goto loser;
    }
    data = get_data_response->GetData();

    if (!(get_data_response->GetSW1() == 0x90 && 
        get_data_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetData",
            "Bad Response");
	goto loser;
    }

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( get_data_request_msg != NULL ) {
        delete get_data_request_msg;
        get_data_request_msg = NULL;
    }
    if( get_data_response_msg != NULL ) {
        delete get_data_response_msg;
        get_data_response_msg = NULL;
    }

    return status;
}

Buffer *RA_Processor::ListObjects(RA_Session *session, BYTE seq)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *request_msg = NULL;
    RA_Token_PDU_Response_Msg *response_msg = NULL;
    List_Objects_APDU *list_objects_apdu = NULL;
    Buffer get_status_data;

    list_objects_apdu =
        new List_Objects_APDU(seq);
    request_msg =
        new RA_Token_PDU_Request_Msg(list_objects_apdu);
    session->WriteMsg(request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::ListObjects",
        "Sent request_msg");

    response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::ListObjects",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::ListObjects", 
		"Invalid Message Type");
           goto loser;
    }
    response = response_msg->GetResponse();
    if (response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::ListObjects", 
		"No Response From Token");
           goto loser;
    }

    if (!(response->GetSW1() == 0x90 && 
        response->GetSW2() == 0x00)) {
  //  	RA::Error(LL_PER_PDU, "RA_Processor::ListObjects",
  //         "Bad Response");
	goto loser;
    }

    data = response->GetData();

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( request_msg != NULL ) {
        delete request_msg;
        request_msg = NULL;
    }
    if( response_msg != NULL ) {
        delete response_msg;
        response_msg = NULL;
    }

    return status;
}

/**
 * GetStatus  
 */
Buffer *RA_Processor::GetStatus(RA_Session *session, BYTE p1, BYTE p2)
{
    Buffer data;
    Buffer *status = NULL;
    APDU_Response *get_status_response = NULL;
    RA_Token_PDU_Request_Msg *get_status_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_status_response_msg = NULL;
    Get_Status_APDU *get_status_apdu = NULL;
    Buffer get_status_data;

    get_status_apdu =
        new Get_Status_APDU();
    get_status_request_msg =
        new RA_Token_PDU_Request_Msg(get_status_apdu);
    session->WriteMsg(get_status_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetStatus",
        "Sent get_status_request_msg");

    get_status_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_status_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetStatus",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_status_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetStatus", 
		"Invalid Message Type");
           goto loser;
    }
    get_status_response =
        get_status_response_msg->GetResponse();
    if (get_status_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetStatus", 
		"No Response From Token");
           goto loser;
    }
    data = get_status_response->GetData();

    if (!(get_status_response->GetSW1() == 0x90 && 
        get_status_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetStatus",
            "Bad Response");
	goto loser;
    }

    status = new Buffer(data.substr(0, data.size()));

loser:

    if( get_status_request_msg != NULL ) {
        delete get_status_request_msg;
        get_status_request_msg = NULL;
    }
    if( get_status_response_msg != NULL ) {
        delete get_status_response_msg;
        get_status_response_msg = NULL;
    }

    return status;
}

int RA_Processor::CreatePin(RA_Session *session, BYTE pin_number, 
		BYTE max_retries, char *pin)
{
    int rc = -1;
    Create_Pin_APDU *create_pin_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::IsPinPresent",
        "Secure_Channel::IsPinPresent");
    Buffer pin_buffer = Buffer((BYTE*)pin, strlen(pin));
    create_pin_apdu = new Create_Pin_APDU(pin_number, max_retries, 
		    pin_buffer);

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        create_pin_apdu);
    session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::CreatePin",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::CreatePin",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::CreatePin", 
		"Invalid Message Type");
           goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::CreatePin",
            "No Response From Token");
        goto loser;
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}
int RA_Processor::IsPinPresent(RA_Session *session, BYTE pin_number)
{
    int rc = -1;
    Buffer data;
    List_Pins_APDU *list_pins_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::IsPinPresent",
        "Secure_Channel::IsPinPresent");
    list_pins_apdu = new List_Pins_APDU(2);

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        list_pins_apdu);
    session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::IsPinPresent",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::IsPinReset",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::IsPinReset", 
		"Invalid Message Type");
           goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::IsPinReset",
            "No Response From Token");
        goto loser;
    }
    data = response->GetData();
    if (data.size() < 2) { 
  	RA::Error(LL_PER_PDU, "Secure_Channel::IsPinReset", 
		"Invalid Response From Token");
          goto loser;
    }

    if (pin_number < 8) {
       rc = ((((BYTE*)data)[1] & (1 << pin_number)) > 0);
    } else {
       rc = ((((BYTE*)data)[0] & (1 << (pin_number - 8))) > 0);
    }

loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}

/**
 * Select applet.
 *
 * Global Platform Open Platform Card Specification 
 * Version 2.0.1 Page 9-22
 *
 * Sample Data:
 *
 * _____________ CLA
 * |  __________ INS
 * |  |  _______ P1
 * |  |  |  ____ P2
 * |  |  |  |  _ Len
 * |  |  |  |  |
 * 00 A4 04 00 07
 * 53 4C 42 47 49 4E 41
 */
int RA_Processor::SelectApplet(RA_Session *session, BYTE p1, BYTE p2, Buffer *aid)
{
    int rc = 0;
    APDU_Response *select_response = NULL;
    RA_Token_PDU_Request_Msg *select_request_msg = NULL;
    RA_Token_PDU_Response_Msg *select_response_msg = NULL;
    Select_APDU *select_apdu = NULL;

    if (aid != NULL) {
      RA::DebugBuffer(LL_PER_PDU, "RA_Processor::SelectApplet",
		      "RA_Processor::SelectApplet with aid= ", aid);
    }

    select_apdu = new Select_APDU(p1, p2, *aid);
    select_request_msg =
        new RA_Token_PDU_Request_Msg(select_apdu);
    session->WriteMsg(select_request_msg);

    RA::Debug(LL_PER_PDU, "RA_Processor::SelectApplet",
        "Sent select_request_msg");

    select_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (select_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::SelectApplet",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (select_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"Invalid Message Type");
           goto loser;
    }
    select_response = select_response_msg->GetResponse();
    if (select_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"No Response From Token");
           goto loser;
    }
    if (select_response->GetData().size() < 2) { 
  	RA::Error(LL_PER_PDU, "Secure_Channel::SelectApplet", 
		"Invalid Response From Token");
          goto loser;
    }
    if (!(select_response->GetSW1() == 0x90 && 
        select_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::SelectApplet",
            "Bad Response");
	goto loser;
    }


loser:
    if( select_request_msg != NULL ) {
        delete select_request_msg;
        select_request_msg = NULL;
    }
    if( select_response_msg != NULL ) {
        delete select_response_msg;
        select_response_msg = NULL;
    }

    return rc;
}

/**
 * Get Build ID from Net Key Applet.
 * @returns a buffer with 4 bytes of data. This is the applet ID. 
 *    The caller is responsible for freeing the buffer with 
 *    the 'delete' operator.
 */
Buffer *RA_Processor::GetAppletVersion(RA_Session *session)
{
    Buffer data;
    Buffer *buildID = NULL;
    APDU_Response *get_version_response = NULL;
    RA_Token_PDU_Request_Msg *get_version_request_msg = NULL;
    RA_Token_PDU_Response_Msg *get_version_response_msg = NULL;
    Get_Version_APDU *get_version_apdu = NULL;
    Buffer get_version_data;

    get_version_apdu =
        new Get_Version_APDU();
    get_version_request_msg =
        new RA_Token_PDU_Request_Msg(get_version_apdu);
    session->WriteMsg(get_version_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::GetAppletVersion",
        "Sent get_version_request_msg");

    get_version_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (get_version_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (get_version_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion", 
		"Invalid Message Type");
           goto loser;
    }
    get_version_response =
        get_version_response_msg->GetResponse();
    if (get_version_response == NULL) { 
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetAppletVersion", 
		"No Response From Token");
           goto loser;
    }
    data = get_version_response->GetData();
    if (!(get_version_response->GetSW1() == 0x90 && 
        get_version_response->GetSW2() == 0x00)) {
    	RA::Error(LL_PER_PDU, "RA_Processor::GetAppletVersion",
            "Bad Response");
	goto loser;
    }

    /* Sample: 3FBAB4BF9000 */
    if (data.size() != 6) {
	   RA::Error(LL_PER_PDU, "Secure_Channel::GetAppletVersion", 
		"Invalid Applet Version");
	    goto loser;
    }

    buildID = new Buffer(data.substr(0, 4));

/*
    buildID = (get_version_data[0] << 24) | (get_version_data[1] << 16) |
	      (get_version_data[2] << 8) | get_version_data[3];

*/ 

loser:

    if( get_version_request_msg != NULL ) {
        delete get_version_request_msg;
        get_version_request_msg = NULL;
    }
    if( get_version_response_msg != NULL ) {
        delete get_version_response_msg;
        get_version_response_msg = NULL;
    }
    return buildID;
}

/*
 * this one sets the security level
 */
Secure_Channel *RA_Processor::SetupSecureChannel(RA_Session *session, 
     BYTE key_version, BYTE key_index, SecurityLevel security_level,
     const char *connId)
{
    Secure_Channel *channel = SetupSecureChannel(session, key_version, key_index, connId);
    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel","Resetting security level ...");

    /* Bugscape Bug #55774: Prevent NetKey RA from crashing . . . */
    if( channel != NULL ) {
        channel->SetSecurityLevel(security_level);
    } else {
        RA::Error( LL_PER_PDU, "RA_Processor::SetupSecureChannel", "%s %s",
			       "Failed to create a secure channel - potentially due to an",
                   "RA/TKS key mismatch or differing RA/TKS key versions." );
    }
    return channel;
  
}

int RA_Processor::InitializeUpdate(RA_Session *session, 
     BYTE key_version, BYTE key_index, 
     Buffer &key_diversification_data,
     Buffer &key_info_data,
     Buffer &card_challenge,
     Buffer &card_cryptogram,
     Buffer &host_challenge)
{
    int rc = -1;
    APDU_Response *initialize_update_response = NULL;
    RA_Token_PDU_Request_Msg *initialize_update_request_msg = NULL;
    RA_Token_PDU_Response_Msg *initialize_update_response_msg = NULL;
    Initialize_Update_APDU *initialize_update_apdu = NULL;
    Buffer update_response_data;

    RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "RA_Processor::InitializeUpdate");

    if (Util::GetRandomChallenge(host_challenge) != PR_SUCCESS)
    {
        RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Failed to generate host challenge");
        goto loser;
    }
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Generated Host Challenge",
        &host_challenge);

    initialize_update_apdu =
        new Initialize_Update_APDU(key_version, key_index, host_challenge);
    initialize_update_request_msg =
        new RA_Token_PDU_Request_Msg(initialize_update_apdu);
    session->WriteMsg(initialize_update_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Sent initialize_update_request_msg");

    initialize_update_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (initialize_update_response_msg == NULL)
    {
    	RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (initialize_update_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate", 
		"Invalid Message Type");
           goto loser;
    }
    initialize_update_response =
        initialize_update_response_msg->GetResponse();
    update_response_data = initialize_update_response->GetData();

    if (!(initialize_update_response->GetSW1() == 0x90 && 
        initialize_update_response->GetSW2() == 0x00)) {
    	RA::Debug(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Key version mismatch - key changeover to follow");
	goto loser;
    }

    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Update Response Data", &update_response_data);

    /**
     * Initialize Update response:
     *   Key Diversification Data - 10 bytes
     *   Key Information Data - 2 bytes
     *   Card Challenge - 8 bytes
     *   Card Cryptogram - 8 bytes
     */
    if (initialize_update_response->GetData().size() < 10) {
    	RA::Error(LL_PER_PDU, "RA_Processor::InitializeUpdate",
            "Invalid Initialize Update Response Size");
	goto loser;
    }
    key_diversification_data = Buffer(update_response_data.substr(0, 10));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Key Diversification Data", &key_diversification_data);
    key_info_data = Buffer(update_response_data.substr(10, 2));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Key Info Data", &key_info_data);
    card_challenge = Buffer(update_response_data.substr(12, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Card Challenge", &card_challenge);
    card_cryptogram = Buffer(update_response_data.substr(20, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::InitializeUpdate",
        "Card Cryptogram", &card_cryptogram);

    rc = 1;

loser:
    if( initialize_update_request_msg != NULL ) {
        delete initialize_update_request_msg;
        initialize_update_request_msg = NULL;
    }
    if( initialize_update_response_msg != NULL ) {
        delete initialize_update_response_msg;
        initialize_update_response_msg = NULL;
    }

    return rc;
}

/**
 * Setup secure channel between RA and the token.
 */
Secure_Channel *RA_Processor::SetupSecureChannel(RA_Session *session, 
     BYTE key_version, BYTE key_index, const char *connId)
{
    Secure_Channel *channel = NULL;
    APDU_Response *initialize_update_response = NULL;
    RA_Token_PDU_Request_Msg *initialize_update_request_msg = NULL;
    RA_Token_PDU_Response_Msg *initialize_update_response_msg = NULL;
    Initialize_Update_APDU *initialize_update_apdu = NULL;
    Buffer update_response_data;
    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;

    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "RA_Processor::Setup_Secure_Channel");

    if (Util::GetRandomChallenge(host_challenge) != PR_SUCCESS)
    {
        RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Failed to generate host challenge");
        goto loser;
    }
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Generated Host Challenge",
        &host_challenge);

    initialize_update_apdu =
        new Initialize_Update_APDU(key_version, key_index, host_challenge);
    initialize_update_request_msg =
        new RA_Token_PDU_Request_Msg(initialize_update_apdu);
    session->WriteMsg(initialize_update_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Sent initialize_update_request_msg");

    initialize_update_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (initialize_update_response_msg == NULL)
    {
    	RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (initialize_update_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
	   RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel", 
		"Invalid Message Type");
           goto loser;
    }
    initialize_update_response =
        initialize_update_response_msg->GetResponse();
    update_response_data = initialize_update_response->GetData();

    if (!(initialize_update_response->GetSW1() == 0x90 && 
        initialize_update_response->GetSW2() == 0x00)) {
    	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Key version mismatch - key changeover to follow");
	goto loser;
    }

    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Update Response Data", &update_response_data);

    /**
     * Initialize Update response:
     *   Key Diversification Data - 10 bytes
     *   Key Information Data - 2 bytes
     *   Card Challenge - 8 bytes
     *   Card Cryptogram - 8 bytes
     */
    if (initialize_update_response->GetData().size() < 28) {
    	RA::Error(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
            "Invalid Initialize Update Response Size");
	goto loser;
    }
    key_diversification_data = Buffer(update_response_data.substr(0, 10));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Key Diversification Data", &key_diversification_data);
    key_info_data = Buffer(update_response_data.substr(10, 2));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Key Info Data", &key_info_data);
    card_challenge = Buffer(update_response_data.substr(12, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Card Challenge", &card_challenge);
    card_cryptogram = Buffer(update_response_data.substr(20, 8));
    RA::DebugBuffer(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "Card Cryptogram", &card_cryptogram);

    channel = GenerateSecureChannel(
        session, connId,
        key_diversification_data,
        key_info_data,
        card_challenge,
        card_cryptogram,
        host_challenge);

loser:
    if( initialize_update_request_msg != NULL ) {
        delete initialize_update_request_msg;
        initialize_update_request_msg = NULL;
    }
    if( initialize_update_response_msg != NULL ) {
        delete initialize_update_response_msg;
        initialize_update_response_msg = NULL;
    }

    return channel;
} /* SetupSecureChannel */

/**
 * Requests secure ID.
 */
SecureId *RA_Processor::RequestSecureId(RA_Session *session)
{
    SecureId *secure_id = NULL;
    RA_SecureId_Request_Msg *secureid_request_msg = NULL;
    RA_SecureId_Response_Msg *secureid_response_msg = NULL;
    char *value;
    char *pin;

    RA::Debug(LL_PER_PDU, "RA_Processor::SecureId_Request",
        "RA_Processor::SecureId_Request");

    secureid_request_msg = new RA_SecureId_Request_Msg(
        0 /* pin_required */, 0 /* next_value */);
    session->WriteMsg(secureid_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::SecureId_Request",
        "Sent secureid_request_msg");

    secureid_response_msg = (RA_SecureId_Response_Msg *)
        session->ReadMsg();
    if (secureid_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::SecureId_Request",
            "No SecureID Response Msg Received");
        goto loser;
    }

    if (secureid_response_msg->GetType() != MSG_SECUREID_RESPONSE) {
            RA::Error("Secure_Channel::SecureId_Request",
            "Invalid Msg Type");
            goto loser;
    }

    value = secureid_response_msg->GetValue();
    pin = secureid_response_msg->GetPIN();

    secure_id = new SecureId(value, pin);

loser:

    if( secureid_request_msg != NULL ) {
        delete secureid_request_msg;
        secureid_request_msg = NULL;
    }
    if( secureid_response_msg != NULL ) {
        delete secureid_response_msg;
        secureid_response_msg = NULL;
    }
    return secure_id;
} /* RequestSecureId */

/**
 * Requests new pin for token.
 */
char *RA_Processor::RequestNewPin(RA_Session *session, unsigned int min, unsigned int max)
{
    char *new_pin = NULL;
    RA_New_Pin_Request_Msg *new_pin_request_msg = NULL;
    RA_New_Pin_Response_Msg *new_pin_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::New_Pin_Request",
        "RA_Processor::New_Pin_Request");

    new_pin_request_msg = new RA_New_Pin_Request_Msg(
        min, max);
    session->WriteMsg(new_pin_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::New_Pin_Request",
        "Sent new_pin_request_msg");

    new_pin_response_msg = (RA_New_Pin_Response_Msg *)
        session->ReadMsg();
    if (new_pin_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "No New Pin Response Msg Received");
        goto loser;
    }

    if (new_pin_response_msg->GetType() != MSG_NEW_PIN_RESPONSE) {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "Invalid Message Type");
        goto loser;
    }

    if (new_pin_response_msg->GetNewPIN() == NULL) {
        RA::Error(LL_PER_PDU, "RA_Processor::New_Pin_Request",
            "No New Pin");
        goto loser;
    }

    new_pin = PL_strdup(new_pin_response_msg->GetNewPIN());

    if (strlen(new_pin) < min) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
          "The length of the new pin is shorter than the mininum length (%d)", min);
        if( new_pin != NULL ) {
            PL_strfree( new_pin );
            new_pin = NULL;
        }
        new_pin = NULL;
        goto loser;
    } else if (strlen(new_pin) > max) {
        RA::Error(LL_PER_PDU, "RA_Pin_Reset_Processor::Process",
          "The length of the new pin is longer than the maximum length (%d)", max);
        if( new_pin != NULL ) {
            PL_strfree( new_pin );
            new_pin = NULL;
        }
        new_pin = NULL;
        goto loser;
    }

loser:

    if( new_pin_request_msg != NULL ) {
        delete new_pin_request_msg;
        new_pin_request_msg = NULL;
    }
    if( new_pin_response_msg != NULL ) {
        delete new_pin_response_msg;
        new_pin_response_msg = NULL;
    }

    return new_pin;
} /* RequestNewPin */

/**
 * Requests A Security Question (ASQ) from user.
 */
char *RA_Processor::RequestASQ(RA_Session *session, char *question)
{
    char *answer = NULL;
    RA_ASQ_Request_Msg *asq_request_msg = NULL;
    RA_ASQ_Response_Msg *asq_response_msg = NULL;

    RA::Debug(LL_PER_PDU, "RA_Processor::ASQ_Request",
        "RA_Processor::ASQ_Request");

    asq_request_msg = new RA_ASQ_Request_Msg(question);
    session->WriteMsg(asq_request_msg);
    RA::Debug(LL_PER_PDU, "RA_Processor::ASQ_Request",
        "Sent asq_request_msg");

    asq_response_msg = (RA_ASQ_Response_Msg *)
        session->ReadMsg();
    if (asq_response_msg == NULL)
    {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "No ASQ Response Msg Received");
        goto loser;
    }
    if (asq_response_msg->GetType() != MSG_ASQ_RESPONSE) {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "Invalid Message Type");
        goto loser;
    }

    if (asq_response_msg->GetAnswer() == NULL) {
        RA::Error(LL_PER_PDU, "RA_Processor::ASQ_Request",
            "No ASQ Answer");
        goto loser;
    }
    answer = PL_strdup(asq_response_msg->GetAnswer());

loser:
    if( asq_request_msg != NULL ) {
        delete asq_request_msg;
        asq_request_msg = NULL;
    }
    if( asq_response_msg != NULL ) {
        delete asq_response_msg;
        asq_response_msg = NULL;
    }

    return answer;
} /* RequestASQ */

/**
 * Creates a secure channel between RA and the token.
 * challenges are sent to TKS which generates
 * host cryptogram, and session key.
 */
Secure_Channel *RA_Processor::GenerateSecureChannel(
    RA_Session *session, const char *connId,
    Buffer &key_diversification_data, /* CUID */
    Buffer &key_info_data,
    Buffer &card_challenge,
    Buffer &card_cryptogram,
    Buffer &host_challenge)
{
    PK11SymKey *session_key = NULL;
    Buffer *host_cryptogram = NULL;
    char configname[256];

    RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
        "RA_Processor::GenerateSecureChannel");

    PK11SymKey *enc_session_key = NULL;


    // desKey_s will be assigned to channel and will be destroyed when channel closed
    char *drm_desKey_s = NULL;
    char *kek_desKey_s = NULL;
    char *keycheck_s = NULL;

    session_key = RA::ComputeSessionKey(session, key_diversification_data, 
                                        key_info_data, card_challenge,
                                        host_challenge, &host_cryptogram, 
		                                card_cryptogram, &enc_session_key,
                                        &drm_desKey_s, &kek_desKey_s,
                                        &keycheck_s, connId);
    if (session_key == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get session_key");
         return NULL;
    }

    // is serversideKeygen on?
    PR_snprintf((char *) configname, 256, "conn.%s.serverKeygen", connId);
    bool serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, false);

    if (serverKeygen) {
      if ((drm_desKey_s == "") || (drm_desKey_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get drm_desKey_s");
	return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - drm_desKey_s = %s", drm_desKey_s);
      }
      if ((kek_desKey_s == "") || (kek_desKey_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get kek_desKey_s");
	return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - kek_desKey_s = %s", kek_desKey_s);
      }
      if ((keycheck_s == "") || (keycheck_s == NULL)) {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - did not get keycheck_s");
	return NULL;
    }

    if (enc_session_key == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get enc_session_key");
         return NULL;
    }
    if (host_cryptogram == NULL) {
      RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
	  "RA_Processor::GenerateSecureChannel - did not get host_cryptogram");
         return NULL;
      } else {
	RA::Debug(LL_PER_PDU, "RA_Processor::Setup_Secure_Channel",
		  "RA_Processor::GenerateSecureChannel - keycheck_s = %s", keycheck_s);
      }
    }
/*
    host_cryptogram = RA::ComputeHostCryptogram(
        card_challenge, host_challenge);
*/


    Secure_Channel *channel = new Secure_Channel(session, session_key,
						 enc_session_key,
						 drm_desKey_s, kek_desKey_s, keycheck_s,
        key_diversification_data, key_info_data,
        card_challenge, card_cryptogram,
        host_challenge, *host_cryptogram);

    if( host_cryptogram != NULL ) {
      delete host_cryptogram;
      host_cryptogram = NULL;
    }

    if (channel != NULL) {
        // this can be overridden by individual processor later
        channel->SetSecurityLevel(RA::GetGlobalSecurityLevel());
    } else {
        if( session_key != NULL ) {
            PK11_FreeSymKey( session_key );
            session_key = NULL;
        }
        if( enc_session_key != NULL ) {
            PK11_FreeSymKey( enc_session_key );
            enc_session_key = NULL;
        }

    }

    RA::Debug(LL_PER_PDU, "RA_Processor::GenerateSecureChannel", "complete");
    return channel;
} /* GenerateSecureChannel */

int RA_Processor::CreateKeySetData(Buffer &CUID, Buffer &version, 
  Buffer &NewMasterVer, Buffer &out, const char *connid)
{
    char body[5000];
    char configname[256];
    HttpConnection *tksConn = NULL;
    tksConn = RA::GetTKSConn(connid);
    if (tksConn == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Processor::CreateKeySetData", "Failed to get TKSConnection %s", connid);
        RA::Error(LL_PER_PDU, "RA_Processor::CreateKeySetData", "Failed to get TKSConnection %s", connid);
        return -1;
    } else {
        // PRLock *tks_lock = RA::GetTKSLock();
        int tks_curr = RA::GetCurrentIndex(tksConn);
        int currRetries = 0;
        char *cuid = Util::SpecialURLEncode(CUID);
        char *versionID = Util::SpecialURLEncode(version);
        char *masterV = Util::SpecialURLEncode(NewMasterVer);

        PR_snprintf((char *)configname, 256, "conn.%s.keySet", connid);
        const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname);

        PR_snprintf((char *)body, 5000,
           "newKeyInfo=%s&CUID=%s&KeyInfo=%s&keySet=%s", masterV, cuid, versionID,keySet);

        PR_snprintf((char *)configname, 256, "conn.%s.servlet.createKeySetData", connid);
        const char *servletID = RA::GetConfigStore()->GetConfigAsString(configname);

        if( cuid != NULL ) {
            PR_Free( cuid );
            cuid = NULL;
        }
        if( versionID != NULL ) {
            PR_Free( versionID );
            versionID = NULL;
        }
        if( masterV != NULL ) {
            PR_Free( masterV );
            masterV = NULL;
        }

        tks_curr = RA::GetCurrentIndex(tksConn);

        PSHttpResponse * response = tksConn->getResponse(tks_curr, servletID, body);
        ConnectionInfo *connInfo = tksConn->GetFailoverList();
        char **hostport = connInfo->GetHostPortList();

        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The CreateKeySetData response from TKS ",
              "at %s is NULL.", hostport[tks_curr]);
        else
            RA::Debug(LL_PER_PDU, "The CreateKeySetData response from TKS ",
              "at % is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());
            tks_curr = RA::GetCurrentIndex(tksConn);

            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ",
              "at %s for createKeySetData.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
                RA::Error(LL_PER_PDU, "RA_Processor::CreateKeySetData","Failed connecting to TKS after %d retries", currRetries);
                if (tksConn != NULL) {
                    RA::ReturnTKSConn(tksConn);
                }
                return -1;
            }
            response = tksConn->getResponse(tks_curr, servletID, body);
        }

        int status = 0;

        Buffer *keydataset = NULL;
        if (response != NULL) {
            RA::Debug(LL_PER_PDU,"Response is not ","NULL");
            char * content = response->getContent();
            if (content == NULL) {
                RA::Debug(LL_PER_PDU,"TKSConnection::CreateKeySetData","Content Is NULL");
            } else {
                RA::Debug(LL_PER_PDU,"TKSConnection::CreateKeySetData","Content Is '%s'",
                                        content);
            }
            if (content != NULL) {
                char *statusStr = strstr((char *)content, "status=0&");
                if (statusStr == NULL) {
                    status = 1;
                    char *p = strstr((char *)content, "status=");
                    if(p != NULL) {
                        status = int(p[7]) - 48;
		    } else {
			status = 4;
                        return -1;
		    }
                } else {
                    status = 0;
                    char *p = &content[9];
                    char *rcStr = strstr((char *)p, "keySetData=");
                    if (rcStr != NULL) {
                        rcStr = &rcStr[11];
                        if (!strcmp(rcStr, "%00")) {
                            return -1;
                        }
                        keydataset = Util::URLDecode(rcStr);
                    }
                }
            }
        }

        if (keydataset == NULL)
        {
            RA::Debug(LL_PER_PDU, "RA_Processor:CreateKeySetData",
              "Key Set Data is NULL");

               return -1;
        }

        RA::Debug(LL_PER_PDU, "RA_Processor:CreateKeySetData", "Status of CreateKeySetData=%d", status);
        RA::Debug(LL_PER_PDU, "finish CreateKeySetData", "");

        if (status > 0) {
	    if (tksConn != NULL) {
                RA::ReturnTKSConn(tksConn);
	    }
            return -1;
	} else {
            out = *keydataset;
            if( keydataset != NULL ) {
                delete keydataset;
                keydataset = NULL;
            }
        }

        if( response != NULL ) {
            response->freeContent();
            delete response;
            response = NULL;
        }

	if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	}
        return 1;
    }
        BYTE kek_key[] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
        BYTE key[] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
    Buffer old_kek_key(kek_key, 16);
    Buffer new_auth_key(key, 16);
    Buffer new_mac_key(key, 16);
    Buffer new_kek_key(key, 16);


        Util::CreateKeySetData(
             NewMasterVer,
             old_kek_key,
             new_auth_key,
             new_mac_key,
             new_kek_key,
             out);

	if (tksConn != NULL) {
		RA::ReturnTKSConn(tksConn);
	}
   return 1;
}


/**
 * Input data wrapped by KEK key in TKS.
 */
int RA_Processor::EncryptData(Buffer &CUID, Buffer &version, Buffer &in, Buffer &out, const char *connid)
{
    char body[5000];
    char configname[256];
#define PLAINTEXT_CHALLENGE_SIZE 16
	// khai, here we wrap the input with the KEK key
	// in TKS
        HttpConnection *tksConn = NULL;
        char kek_key[16] = {
                0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b,
                0x4c, 0x4d, 0x4e, 0x4f
        };
    int status = 0;

    tksConn = RA::GetTKSConn(connid);
    if (tksConn == NULL) {
        RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData", "Failed to get TKSConnection %s", connid);
        RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData", "Failed to get TKSConnection %s", connid);
        return -1;
    } else {
        int tks_curr = RA::GetCurrentIndex(tksConn);
        int currRetries = 0;
        char *data = NULL;
        Buffer *zerob = new Buffer(PLAINTEXT_CHALLENGE_SIZE, (BYTE)0);
        if (!(in == *zerob))
          data = Util::SpecialURLEncode(in);
        else
          RA::Debug(LL_PER_PDU, "RA_Processor::EncryptData","Challenge to be generated on TKS");

        if (zerob != NULL) {
            delete zerob;
        }

        char *cuid = Util::SpecialURLEncode(CUID);
        char *versionID = Util::SpecialURLEncode(version);

        PR_snprintf((char *)configname, 256, "conn.%s.keySet", connid);
        const char *keySet = RA::GetConfigStore()->GetConfigAsString(configname);

        PR_snprintf((char *)body, 5000, "data=%s&CUID=%s&KeyInfo=%s&keySet=%s",
          ((data != NULL)? data:""), cuid, versionID,keySet);
        PR_snprintf((char *)configname, 256, "conn.%s.servlet.encryptData", connid);
        const char *servletID = RA::GetConfigStore()->GetConfigAsString(configname);

        if( cuid != NULL ) {
            PR_Free( cuid );
            cuid = NULL;
        }
        if( versionID != NULL ) {
            PR_Free( versionID );
            versionID = NULL;
        }

        PSHttpResponse *response = tksConn->getResponse(tks_curr, servletID, body);
        ConnectionInfo *connInfo = tksConn->GetFailoverList();
        char **hostport = connInfo->GetHostPortList();
        if (response == NULL)
            RA::Debug(LL_PER_PDU, "The encryptedData response from TKS ",
              "at %s is NULL.", hostport[tks_curr]);
        else
            RA::Debug(LL_PER_PDU, "The encryptedData response from TKS ",
              "at %s is not NULL.", hostport[tks_curr]);

        while (response == NULL) {
            RA::Failover(tksConn, connInfo->GetHostPortListLen());
            tks_curr = RA::GetCurrentIndex(tksConn);
            RA::Debug(LL_PER_PDU, "RA is reconnecting to TKS ",
              "at %s for encryptData.", hostport[tks_curr]);

            if (++currRetries >= tksConn->GetNumOfRetries()) {
                RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
                RA::Error(LL_PER_PDU, "RA_Processor::EncryptData", "Failed connecting to TKS after %d retries", currRetries);
                if (tksConn != NULL) {
		          RA::ReturnTKSConn(tksConn);
	            }
                return -1;
            }
            response = tksConn->getResponse(tks_curr, servletID, body);
        }

        Buffer *encryptedData = NULL;
        // preEncData is only useful when data is null, and data is to be randomly
        // generated on TKS
        Buffer *preEncData = NULL;
        status = 0;
        if (response != NULL) {
            RA::Debug(LL_PER_PDU, "EncryptData Response is not ","NULL");
            char *content = response->getContent();
            if (content != NULL) {
                char *statusStr = strstr((char *)content, "status=0&");
                if (statusStr == NULL) {
                    char *p = strstr((char *)content, "status=");

                    if(p != NULL) {
                        status = int(p[7]) - 48;
		    } else {
			status = 4;
                        return -1;
		    }
                } else {
                    status = 0;
                    char *p = &content[9];
                    // get pre-encryption data
                    char *preStr = strstr((char *)p, "data=");
                    if (preStr != NULL) {
                      p = &preStr[5];
                      char pstr[PLAINTEXT_CHALLENGE_SIZE*3+1];
                      strncpy(pstr, p, PLAINTEXT_CHALLENGE_SIZE*3); 
                      pstr[PLAINTEXT_CHALLENGE_SIZE*3] = '\0';
                      preEncData = Util::URLDecode(pstr);
//RA::DebugBuffer("RA_Processor::EncryptData", "preEncData=", preEncData);
                    }

                    // get encrypted data
                    p = &content[9];
                    char *rcStr = strstr((char *)p, "encryptedData=");
                    if (rcStr != NULL) {
                        rcStr = &rcStr[14];
                        encryptedData = Util::URLDecode(rcStr);
//RA::DebugBuffer("RA_Processor::EncryptData", "encryptedData=", encryptedData);
                    }
                }
            }
        }
        if (encryptedData == NULL)
            RA::Debug(LL_PER_PDU, "RA_Processor:GetEncryptedData",
              "Encrypted Data is NULL");

        RA::Debug(LL_PER_PDU, "EncryptedData ", "status=%d", status);
        RA::Debug(LL_PER_PDU, "finish EncryptedData", "");
        if ((status > 0) || (preEncData == NULL) || (encryptedData == NULL)) {
            if (tksConn != NULL) {
                RA::ReturnTKSConn(tksConn);
	        }
            if( data != NULL ) {
                PR_Free( data );
                data = NULL;
            }
            return -1;   
	    } else {
            out = *encryptedData;
            if( encryptedData != NULL ) {
                delete encryptedData;
                encryptedData = NULL;
            }
            if (data != NULL) {
                RA::Debug(LL_PER_PDU, "EncryptedData ", "challenge overwritten by TKS");
                PR_Free( data );
                data = NULL;
            }
            in = *preEncData;

            if( preEncData != NULL ) {
                delete preEncData;
                preEncData = NULL;
            }
        }
        if( response != NULL ) {
            response->freeContent();
            delete response;
            response = NULL;
        }

        if (tksConn != NULL) {
            RA::ReturnTKSConn(tksConn);
	    }
        return 1;
    }

	Buffer kek_buffer = Buffer((BYTE*)kek_key, 16);
	status = Util::EncryptData(kek_buffer, in, out);
#if 0
        RA::DebugBuffer(LL_PER_PDU, "RA_Processor::EncryptData", "Encrypted Data",
		&out);
        Buffer out1 = Buffer(16, (BYTE)0);
	status = Util::DecryptData(kek_buffer, out, out1);
        RA::DebugBuffer(LL_PER_PDU, "RA_Processor::EncryptData", "Clear Data",
		&out1);
#endif
        if (tksConn != NULL) {
	    RA::ReturnTKSConn(tksConn);
	}
	return status;
}

/**
 * Process the current session. It does nothing in the base
 * class.
 */
RA_Status RA_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    return STATUS_NO_ERROR;
} /* Process */

