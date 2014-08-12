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

#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

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
#include "main/Buffer.h"
#include "main/RA_Session.h"
#include "apdu/APDU.h"
#include "apdu/APDU_Response.h"
#include "channel/Channel.h"

enum SecurityLevel {
    SECURE_MSG_ANY = 0,
    SECURE_MSG_MAC = 1,
    SECURE_MSG_NONE = 2, // not yet supported
    SECURE_MSG_MAC_ENC = 3
} ;

enum TokenKeyType {
     KEY_TYPE_ENCRYPTION = 0,
     KEY_TYPE_SIGNING = 1,
     KEY_TYPE_SIGNING_AND_ENCRYPTION = 2
};

class Secure_Channel : public Channel
{
  public:

	  Secure_Channel(
		RA_Session *session, 
		PK11SymKey *session_key,
		PK11SymKey *enc_session_key,
		char *drm_des_key_s,
		char *kek_des_key_s,
		char *keycheck_s,
                Buffer &key_diversification_data,
                Buffer &key_info_data,
                Buffer &card_challenge,
                Buffer &card_cryptogram,
                Buffer &host_challenge,
                Buffer &host_cryptogram);

	  ~Secure_Channel();
  public:
          Buffer &GetKeyDiversificationData();
          Buffer &GetKeyInfoData();
          Buffer &GetCardChallenge();
          Buffer &GetCardCryptogram();
          Buffer &GetHostChallenge();
          Buffer &GetHostCryptogram();
	  SecurityLevel GetSecurityLevel();
	  void SetSecurityLevel(SecurityLevel level);
	  char *getDrmWrappedDESKey();
	  char *getKekWrappedDESKey();
	  char *getKeycheck();

  public:
	  int ImportKeyEnc(BYTE priv_key_number, BYTE pub_key_number, Buffer* data);
	  int ImportKey(BYTE key_number);
	  int CreatePin(BYTE pin_number, BYTE max_retries, const char *pin);
	  int ExternalAuthenticate();
	  int SetIssuerInfo(Buffer *info);
	  Buffer GetIssuerInfo();
	  int ResetPin(BYTE pin_number, char *pin);
          int IsPinPresent(BYTE pin_number);
	  int SetLifecycleState(BYTE flag);
	  int StartEnrollment(BYTE p1, BYTE p2, Buffer *wrapped_challenge, 
		Buffer *key_check,
		BYTE alg, int keysize, BYTE option);
	  int ReadBuffer(BYTE *buf, int buf_len);
	  int CreateObject(BYTE *object_id, BYTE* permissions, int len); 
	  int WriteObject(BYTE *objid, BYTE *buf, int buf_len);
	  Buffer *ReadObject(BYTE *objid, int offset, int len);
          int PutKeys(RA_Session *session, BYTE key_version, 
                  BYTE key_index, Buffer *key_data); 
	  int LoadFile(RA_Session *session, BYTE refControl, BYTE blockNum,
		        Buffer *data); 
          int InstallApplet(RA_Session *session,
	                Buffer &packageAID, Buffer &appletAID,
	                BYTE appPrivileges, unsigned int instanceSize, unsigned int appletMemorySize);
          int InstallLoad(RA_Session *session,
	                Buffer& packageAID, Buffer& sdAID, unsigned int fileLen);
	  int DeleteFileX(RA_Session *session, Buffer *aid);
	  int Close();
  public:
          int CreateObject(BYTE *objid, BYTE *perms, Buffer *obj);
          int CreateCertificate(const char *id, Buffer *cert);

          Buffer CreatePKCS11CertAttrsBuffer(TokenKeyType type, const char *id, const char *label, Buffer *keyid);
          int CreatePKCS11CertAttrs(TokenKeyType type, const char *id, const char *label, Buffer *keyid);
          Buffer CreatePKCS11PriKeyAttrsBuffer(TokenKeyType type, const char *id, const char *label, Buffer *keyid, 
                Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix);

          Buffer CreatePKCS11ECCPriKeyAttrsBuffer(TokenKeyType type, const char *id, const char *label, Buffer *keyid,
                SECKEYECParams *ecParams, const char *opType, const char *tokenType, const char *keyTypePrefix);  

          int CreatePKCS11PriKeyAttrs(TokenKeyType type, const char *id, const char *label, Buffer *keyid, 
                Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix);
          Buffer CreatePKCS11PubKeyAttrsBuffer(TokenKeyType type, const char *id, const char *label, Buffer *keyid,
                Buffer *exponent, Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix);

          Buffer CreatePKCS11ECCPubKeyAttrsBuffer(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid, SECKEYECPublicKey *publicKey,
                 SECKEYECParams *ecParams, const char *opType, const char *tokenType, const char *keyTypePrefix);

          int CreatePKCS11PubKeyAttrs(TokenKeyType type, const char *id, const char *label, Buffer *keyid,
                Buffer *exponent, Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix);
	  APDU_Response *SendTokenAPU(APDU *apdu);

  public:
          Buffer *ComputeAPDUMac(APDU *apdu);
	  int ComputeAPDU(APDU *apdu);

  private: 
          PK11SymKey *m_session_key;
          PK11SymKey *m_enc_session_key;
	  char *m_drm_wrapped_des_key_s;
	  char *m_kek_wrapped_des_key_s;
	  char *m_keycheck_s;
	  RA_Session *m_session;
	  Buffer m_icv;
	  Buffer m_cryptogram;
          Buffer m_key_diversification_data;
          Buffer m_key_info_data;
          Buffer m_card_challenge;
          Buffer m_card_cryptogram;
          Buffer m_host_challenge;
          Buffer m_host_cryptogram;
	  SecurityLevel m_security_level;
};

#endif /* SECURE_CHANNEL_H */
