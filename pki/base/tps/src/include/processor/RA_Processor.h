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

#ifndef RA_PROCESSOR_H
#define RA_PROCESSOR_H

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

#include "main/Login.h"
#include "main/SecureId.h"
#include "main/RA_Session.h"
#include "authentication/AuthParams.h"
#include "apdu/APDU.h"
#include "apdu/APDU_Response.h"
#include "channel/Secure_Channel.h"

enum RA_Status {
    STATUS_NO_ERROR=0,
    STATUS_ERROR_SNAC=1,
    STATUS_ERROR_SEC_INIT_UPDATE=2,
    STATUS_ERROR_CREATE_CARDMGR=3,
    STATUS_ERROR_MAC_RESET_PIN_PDU=4,
    STATUS_ERROR_MAC_CERT_PDU=5,
    STATUS_ERROR_MAC_LIFESTYLE_PDU=6,
    STATUS_ERROR_MAC_ENROLL_PDU=7,
    STATUS_ERROR_READ_OBJECT_PDU=8,
    STATUS_ERROR_BAD_STATUS=9,
    STATUS_ERROR_CA_RESPONSE=10,
    STATUS_ERROR_READ_BUFFER_OVERFLOW=11,
    STATUS_ERROR_TOKEN_RESET_PIN_FAILED=12,
    STATUS_ERROR_CONNECTION=13,
    STATUS_ERROR_LOGIN=14,
    STATUS_ERROR_DB=15,
    STATUS_ERROR_TOKEN_DISABLED=16,
    STATUS_ERROR_SECURE_CHANNEL=17,
    STATUS_ERROR_MISCONFIGURATION=18,
    STATUS_ERROR_UPGRADE_APPLET=19,
    STATUS_ERROR_KEY_CHANGE_OVER=20,
    STATUS_ERROR_EXTERNAL_AUTH=21,
    STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND=22,
    STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND=23,
    STATUS_ERROR_PUBLISH=24,
    STATUS_ERROR_LDAP_CONN=25,
    STATUS_ERROR_DISABLED_TOKEN=26,
    STATUS_ERROR_NOT_PIN_RESETABLE=27,
    STATUS_ERROR_CONN_LOST=28,
    STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY=29,
    STATUS_ERROR_NO_SUCH_TOKEN_STATE=30,
    STATUS_ERROR_NO_SUCH_LOST_REASON=31,
    STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE=32,
    STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND=33,
    STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN=34,
    STATUS_ERROR_CONTACT_ADMIN=35,
    STATUS_ERROR_RECOVERY_IS_PROCESSED=36,
    STATUS_ERROR_RECOVERY_FAILED=37,
    STATUS_ERROR_NO_OPERATION_ON_LOST_TOKEN=38,
    STATUS_ERROR_KEY_ARCHIVE_OFF=39,
    STATUS_ERROR_NO_TKS_CONNID=40,
    STATUS_ERROR_UPDATE_TOKENDB_FAILED=41,
    STATUS_ERROR_REVOKE_CERTIFICATES_FAILED=42,
    STATUS_ERROR_NOT_TOKEN_OWNER=43,
    STATUS_ERROR_RENEWAL_IS_PROCESSED=44,
    STATUS_ERROR_RENEWAL_FAILED=45
};

class RA_Processor
{
	public:
		RA_Processor();
		virtual ~RA_Processor();
		virtual RA_Status Process(RA_Session *session, NameValueSet *extensions);
		char *MapPattern(NameValueSet *nv, char *pattern);

		int InitializeUpdate(RA_Session *session,
				BYTE key_version, BYTE key_index,
				Buffer &key_diversification_data,
				Buffer &key_info_data,
				Buffer &card_challenge,
				Buffer &card_cryptogram,
				Buffer &host_challenge);

		int CreatePin(RA_Session *session, BYTE pin_number, BYTE max_retries, char *pin);

		int IsPinPresent(RA_Session *session,BYTE pin_number);

		AuthParams *RequestLogin(RA_Session *session, int invalid_pw, int blocked);
		AuthParams *RequestExtendedLogin(RA_Session *session, int invalid_pw, int blocked, char **parameters, int len, char *title, char *description);

		void StatusUpdate(RA_Session *session, NameValueSet *extensions, int status, const char *info);
		void StatusUpdate(RA_Session *session, int status, const char *info);

		Buffer *GetAppletVersion(RA_Session *session);

		Secure_Channel *SetupSecureChannel(RA_Session *session, BYTE key_version, BYTE key_index, const char *connId);
		Secure_Channel *SetupSecureChannel(RA_Session *session,
				BYTE key_version, BYTE key_index, SecurityLevel security_level, const char *connId);

		SecureId *RequestSecureId(RA_Session *session);

		char *RequestNewPin(RA_Session *session, unsigned int min_len, unsigned int max_len);

		char *RequestASQ(RA_Session *session, char *question);

		int EncryptData(Buffer &cuid, Buffer &versionID, Buffer &in, Buffer &out, const char *connid);

		int CreateKeySetData(
			Buffer &cuid, 
			Buffer &versionID, 
			Buffer &NewMasterVer, 
			Buffer &out, 
			const char *connid);

		bool GetTokenType(
			const char *prefix, 
			int major_version, int minor_version, 
			const char *cuid, const char *msn, 
			NameValueSet *extensions,
			RA_Status &o_status,
			const char *&o_tokenType);

		Buffer *ListObjects(RA_Session *session, BYTE seq);

		Buffer *GetStatus(RA_Session *session, BYTE p1, BYTE p2);

		Buffer *GetData(RA_Session *session);

		int SelectApplet(RA_Session *session, BYTE p1, BYTE p2, Buffer *aid);

		int UpgradeApplet(
				RA_Session *session, 
                char *prefix,
                char *tokenType,
				BYTE major_version, BYTE minor_version, 
				const char *new_version, 
				const char *applet_dir, 
				SecurityLevel security_level, 
				const char *connid, 
				NameValueSet *extensions,
				int start_progress, int end_progress,
                                char **key_version);

		int UpgradeKey(RA_Session *session, BYTE major_version, BYTE minor_version, int new_version);

		int SelectCardManager(RA_Session *session, char *prefix, char *tokenType);

		int FormatMuscleApplet(
				RA_Session *session,
				unsigned short memSize,
				Buffer &PIN0, BYTE pin0Tries,
				Buffer &unblockPIN0, BYTE unblock0Tries,
				Buffer &PIN1, BYTE pin1Tries,
				Buffer &unblockPIN1, BYTE unblock1Tries,
				unsigned short objCreationPermissions,
				unsigned short keyCreationPermissions,
				unsigned short pinCreationPermissions);

		Secure_Channel *GenerateSecureChannel(
				RA_Session *session, const char *connid,
				Buffer &card_diversification_data,
				Buffer &card_key_data,
				Buffer &card_challenge,
				Buffer &card_cryptogram,
				Buffer &host_challenge);
                AuthenticationEntry *GetAuthenticationEntry(
                                const char * a_prefix,
                                const char * a_configname,
                                const char * a_tokenType);

	protected:
		int IsTokenDisabledByTus(Secure_Channel *channel);
};

#endif /* RA_PROCESSOR_H */
