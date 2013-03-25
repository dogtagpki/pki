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

#ifndef RA_ENROLL_PROCESSOR_H
#define RA_ENROLL_PROCESSOR_H

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

#include "main/RA_Session.h"
#include "main/PKCS11Obj.h"
#include "processor/RA_Processor.h"
#include "cms/HttpConnection.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class RA_Enroll_Processor : public RA_Processor
{
    public:
        TPS_PUBLIC RA_Enroll_Processor();
        TPS_PUBLIC ~RA_Enroll_Processor();
    public:
        int ParsePublicKeyBlob(unsigned char *blob,
            unsigned char *challenge,
        SECKEYPublicKey *pk);
        RA_Status DoEnrollment(AuthParams *login, RA_Session *session,
            CERTCertificate **certificates,
            char **origins,
            char **ktypes,
            int pkcs11obj,
            PKCS11Obj * pkcs_objx,
            NameValueSet *extensions,
            int index, int keyTypeNum,
            int start_progress,
            int end_progress,
            Secure_Channel *channel, Buffer *wrapped_challenge,
            const char *tokenType,
            const char *keyType,
            Buffer *key_check,
            Buffer *plaintext_challenge,
            const char *cuid,
            const char *msn,
            const char *khex,
            TokenKeyType key_type,
            const char *profileId,
            const char *userid,
            const char *cert_id,
            const char *publisher_id,
            const char *cert_attr_id,
            const char *pri_attr_id,
            const char *pub_attr_id,
            BYTE se_p1, BYTE se_p2, BYTE algorithm, int keysize, const char *connid, const char *keyTypePrefix,char * applet_version);

        bool DoRenewal(const char *connid,
                const char *profileId,
                CERTCertificate *i_cert,
                CERTCertificate **o_cert, 
                char *error_msg, int *error_code);

        bool GenerateCertificate(AuthParams *login,
                int keyTypeNum, 
                const char *keyTypeValue, 
                int i, 
                RA_Session *session,
                char **origins, 
                char **ktypes, 
                char *tokenType, 
                PKCS11Obj *pkcs11objx, 
                int pkcs11obj_enable, 
                NameValueSet *extensions,
                Secure_Channel *channel, 
                Buffer *wrapped_challenge,
                Buffer *key_check, 
                Buffer *plaintext_challenge,
                char *cuid, 
                char *msn, 
                const char *final_applet_version,
                char *khex, 
                const char *userid, 
                RA_Status &o_status, 
                CERTCertificate **certificates);

		bool GenerateCertsAfterRecoveryPolicy(AuthParams *login,
				RA_Session *session, 
				char **&origins,
				char **&ktypes,
				char *&tokenType, 
				PKCS11Obj *pkcs11objx, 
				int pkcs11obj_enable, 
				NameValueSet *extensions,
				Secure_Channel *channel, 
				Buffer *wrapped_challenge,
				Buffer *key_check, 
				Buffer *plaintext_challenge, 
				char *cuid, 
				char *msn, 
				const char *final_applet_version,
				char *khex, 
				const char *userid,
				RA_Status &o_status, 
				CERTCertificate **&certificates,
                int &o_certNums, char **&tokenTypes);

		bool GenerateCertificates(AuthParams *login,
				RA_Session *session, 
				char **&origins,
				char **&ktypes,
				char *tokenType, 
				PKCS11Obj *pkcs11objx, 
				int pkcs11obj_enable, 
				NameValueSet *extensions,
				Secure_Channel *channel, 
				Buffer *wrapped_challenge,
				Buffer *key_check, 
				Buffer *plaintext_challenge, 
				char *cuid, 
				char *msn, 
				const char *final_applet_version,
				char *khex, 
				const char *userid,
				RA_Status &o_status, 
				CERTCertificate **&certificates,
                int &o_certNums, char **&tokenTypes);

		int DoPublish(
				const char *cuid,
				SECItem *encodedPublicKeyInfo,
				Buffer *cert,
				const char *publisher_id,
				char *applet_version);

		bool ProcessRecovery(AuthParams *login,
				char *reason, 
				RA_Session *session, 
				char **&origins,   
				char **&ktypes,   
				char *tokenType, 
				PKCS11Obj *pkcs11objx, 
				int pkcs11obj_enable, 
				NameValueSet *extensions,
				Secure_Channel *channel, 
				Buffer *wrapped_challenge,
				Buffer *key_check, 
				Buffer *plaintext_challenge, 
				char *cuid,
				char *msn, 
				const char *final_applet_version, 
				char *khex,
				const char *userid, 
				RA_Status &o_status, 
				CERTCertificate **&certificates,
                char *lostTokenCUID,
                int &o_certNums, char **&tokenTypes, char *origTokenType);

                bool ProcessRenewal(AuthParams *login,
                        RA_Session *session, 
                        char **&ktypes,   
                        char **&origins, 
                        char *tokenType, 
                        PKCS11Obj *pkcs11objx, 
                        int pkcs11obj_enable, 
                        Secure_Channel *channel, 
                        const char *cuid,
                        char *msn, 
                        const char *final_applet_version, 
                        const char *userid, 
                        RA_Status &o_status, 
                        CERTCertificate **&certificates,
                       int &o_certNums, char **&tokenTypes);

		bool GetCardManagerAppletInfo(
				RA_Session*, 
				Buffer *, 
				RA_Status&, 
				char*&, 
				char*&, 
				Buffer& );

		bool GetAppletInfo( 
				RA_Session *a_session,   /* in */ 
				Buffer *a_aid ,  /* in */ 
				BYTE &o_major_version, 
				BYTE &o_minor_version, 
				BYTE &o_app_major_version, 
				BYTE &o_app_minor_version);

		bool FormatAppletVersionInfo(
				RA_Session *a_session,
				const char *a_tokenType,
				char *a_cuid,
				BYTE a_app_major_version,
				BYTE a_app_minor_version,
				RA_Status &status,              // out
				char * &o_appletVersion       // out
				);

		bool RequestUserId(
				RA_Session * a_session,
				NameValueSet *extensions,
				const char * a_configname,
				const char * a_tokenType,
				char *a_cuid,
				AuthParams *& o_login,  // out 
				const char *&o_userid,   // out 
				RA_Status &o_status //out 
				);


		bool AuthenticateUser(
				RA_Session * a_session,
				const char * a_configname,
				char *a_cuid,
				NameValueSet *a_extensions,
				const char *a_tokenType,
				AuthParams *& a_login, 
				const char *&o_userid,
				RA_Status &o_status
				);

		bool AuthenticateUserLDAP(
				RA_Session *a_session,
				NameValueSet *extensions,
				char *a_cuid,
				AuthenticationEntry *a_auth,
				AuthParams *& o_login,
				RA_Status &o_status,
                                const char *token_type);

		bool CheckAndUpgradeApplet(
				RA_Session *a_session,
				NameValueSet *a_extensions,
				char *a_cuid,
				const char *a_tokenType,
				char *&o_current_applet_on_token,
				BYTE &o_major_version,
				BYTE &o_minor_version,
				Buffer *a_aid,
                                const char *msn,
                                const char *userid,
				RA_Status &o_status,
                                char **key_version );

		bool CheckAndUpgradeSymKeys(
				RA_Session *session,
				NameValueSet* extensions,
				char *cuid,
				const char *tokenType,
				char *msn,
                                const char* applet_version, 
                                const char* userid,
                                const char* key_version,
				Buffer *a_cardmanagerAID,  /* in */
				Buffer *a_appletAID,       /* in */
				Secure_Channel *&channel,  /* out */
				RA_Status &status          /* out */
				);

		TPS_PUBLIC RA_Status Process(RA_Session *session, NameValueSet *extensions);

	private:
		int GetNextFreeCertIdNumber(PKCS11Obj *pkcs11objx);
                bool isCertRenewable(CERTCertificate *cert, int graceBefore, int graceAfter);
                int UnrevokeRecoveredCert(LDAPMessage *e, char *&statusString);
};

#endif /* RA_ENROLL_PROCESSOR_H */
