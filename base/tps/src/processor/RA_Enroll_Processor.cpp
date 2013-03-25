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

/**
 *  RA_Enroll_Processor handles initialization and enrollment of the token
 */


/* variable naming convention:
 * a_ passed as an 'in' argument to a method
 * o_ passed as an 'out' argument to a method
 * m_ member variable
 */


#include <string.h>
#include <time.h>
#include "pkcs11.h"

// for public key processing
#include "secder.h"
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "base64.h"
#include "nssb64.h"
#include "prlock.h"

#include "cert.h"
#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "main/PKCS11Obj.h"
#include "engine/RA.h"
#include "channel/Secure_Channel.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "processor/RA_Processor.h"
#include "processor/RA_Enroll_Processor.h"
#include "tus/tus_db.h"

#include "cms/CertEnroll.h"
#include "httpClient/httpc/response.h"
#include "main/Memory.h"

#define OP_PREFIX "op.enroll"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

SECStatus PK11_GenerateRandom(unsigned char *,int);
void PrintPRTime(PRTime, const char *);


// This parameter is read from the config file. It is the
// applet build ID which the administrator wants to set as
// the 'latest applet' to upgrade to.
static const char *g_applet_target_version = NULL;


/**
 * this function returns a new allocated string
 * @param cuid a 20 character string. Usually this is 20 hex
 *  digits representing a token CUID.
 * @returns a new string which is basically a copy of the input, but 
 *   with extra colons. The caller is responsible for freeing the 
 *   returned string with PR_Free().
 */

static char *GetPrettyPrintCUID(const char *cuid)
{
	int i,j;
	char *ret = NULL;

	if (cuid == NULL)
		return NULL;
	if (strlen(cuid) != 20) 
		return NULL;
	ret = (char *)PR_Malloc(20+4+1);
	j = 0;
	for (i = 0; i < 24; i++) {
		if (i == 4 || i == 9 || i == 14 || i == 19) {
		    ret[i] = '-';
		} else {
		    ret[i] = cuid[j];
		    j++;
		}
	}
	ret[24] = '\0';
	return ret;
}

static SECItem *
PK11_GetPubIndexKeyID(CERTCertificate *cert) {
    SECKEYPublicKey *pubk;
    SECItem *newItem = NULL;
                                                                                
    pubk = CERT_ExtractPublicKey(cert);
    if (pubk == NULL) return NULL;
                                                                                
    switch (pubk->keyType) {
    case rsaKey:
    newItem = SECITEM_DupItem(&pubk->u.rsa.modulus);
    break;
    case dsaKey:
        newItem = SECITEM_DupItem(&pubk->u.dsa.publicValue);
    break;
    case dhKey:
        newItem = SECITEM_DupItem(&pubk->u.dh.publicValue);
    break;
    case ecKey:
        newItem = SECITEM_DupItem(&pubk->u.ec.publicValue);
    break;
    case fortezzaKey:
    default:
    newItem = NULL; /* Fortezza Fix later... */
    }
    SECKEY_DestroyPublicKey(pubk);
    /* make hash of it */
    return newItem;
}


/**
 * Constructs a processor for handling enrollment operation.
 */
TPS_PUBLIC RA_Enroll_Processor::RA_Enroll_Processor ()
{
}

/**
 * Destructs enrollment processor.
 */
TPS_PUBLIC RA_Enroll_Processor::~RA_Enroll_Processor ()
{
}

RA_Status RA_Enroll_Processor::DoEnrollment(AuthParams *login, RA_Session *session, 
                CERTCertificate **certificates,
                char **origins,
                char **ktypes,
		    int pkcs11obj_enable,
		PKCS11Obj *pkcs_objx,
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
		BYTE se_p1, BYTE se_p2, BYTE algorithm,  int keysize, const char *connid, const char *keyTypePrefix,char * applet_version)
{
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    int len = 0;
    int publish_result = -1;
    Buffer *public_key = NULL;
    SECItem si_mod;
    Buffer *modulus=NULL;
    SECItem *si_kid = NULL;
    Buffer *keyid=NULL;
    SECItem si_exp;
    Buffer *exponent=NULL;
    CertEnroll *certEnroll = NULL;
    Buffer *cert = NULL;
    Buffer CUID = channel->GetKeyDiversificationData();
    const char *label = NULL;
    const char *cuid_label = NULL;
    const char *pattern;
    char configname[256];
    NameValueSet nv;
    const char *pretty_cuid = NULL;

    const char *FN="RA_Enroll_Processor::DoEnrollment";

    char *cert_string = NULL;
    SECItem* encodedPublicKeyInfo = NULL;
    SECItem **ppEncodedPublicKeyInfo = NULL;
	CERTSubjectPublicKeyInfo*  spkix = NULL;

    char *pKey = NULL;
    char *ivParam = NULL;
    char *wrappedPrivKey = NULL;

    const char *drmconnid = NULL;
    bool serverKeygen = false;
    SECKEYPublicKey *pk_p = NULL;

    char audit_msg[512] = "";
    char *keyVersion = NULL;
    char cert_serial[2048] = "";
    char activity_msg[4096] = "";

    float progress_block_size = (float) (end_progress - start_progress) / keyTypeNum;
    RA::Debug(LL_PER_CONNECTION,FN,
	            "Start of keygen/certificate enrollment");

    bool isECC = RA::isAlgorithmECC(algorithm);
    SECKEYECParams  *eccParams = NULL;

    // get key version for audit logs
    if (channel != NULL) {
       if( keyVersion != NULL ) {
           PR_Free( (char *) keyVersion );
           keyVersion = NULL;
       }
       keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    // check if we need to do key generation (by default, overwrite everything)
    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.overwrite", 
		    OP_PREFIX, tokenType, keyType);
      RA::Debug(LL_PER_CONNECTION,FN,
	            "looking for config %s", configname);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
	    // do nothing
      RA::Debug(LL_PER_CONNECTION,FN,
	            "do overwrite");
    } else {
      RA::Debug(LL_PER_CONNECTION,FN,
	            "do not overwrite, if %s exists", cert_id);
      int num_objs = pkcs_objx->PKCS11Obj::GetObjectSpecCount();
      char b[3];
      bool foundObj = false;
      for (int i = 0; i< num_objs; i++) {
	ObjectSpec* os = pkcs_objx->GetObjectSpec(i);
	unsigned long oid = os->GetObjectID();
	b[0] = (char)((oid >> 24) & 0xff);
	b[1] = (char)((oid >> 16) & 0xff);
	b[2] = '\0';
	/*
	RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
		   "object id =%c:%c  b=%s",b[0], b[1], b);
	*/
	if (PL_strcasecmp(cert_id, b) == 0) {
	  foundObj = true;
	  break;
	}
      }


      if (foundObj) {
		// we already have a certificate there, skip enrollment
                RA::Debug(LL_PER_CONNECTION,FN,
	            "Found certficate. Will not overwrite. Skipped enrollment");
		return status;
	} else {
                RA::Debug(LL_PER_CONNECTION,FN,
	            "Certficate not found. Continuing with enrollment");
	}
    }
    
    StatusUpdate(session, extensions, 
		 start_progress + (index * progress_block_size) + 
		 (progress_block_size * 15/100) /* progress */, 
		 "PROGRESS_KEY_GENERATION");

    if (key_type == KEY_TYPE_ENCRYPTION) {
      // do serverSide keygen?
      PR_snprintf((char *)configname, 256, "%s.serverKeygen.enable", keyTypePrefix);
      RA::Debug(LL_PER_CONNECTION,FN,
		"looking for config %s", configname);
      serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, false);
    }

    certEnroll = new CertEnroll();

    if (serverKeygen) {
      RA::Debug(LL_PER_CONNECTION,FN,
        "Private key is to be generated on server");

      PR_snprintf((char *)configname, 256, "%s.serverKeygen.drm.conn", keyTypePrefix);
      RA::Debug(LL_PER_CONNECTION,FN,
        "looking for config %s", configname);
      drmconnid = RA::GetConfigStore()->GetConfigAsString(configname);

      PR_snprintf((char *)configname, 256, "%s.serverKeygen.archive", keyTypePrefix);
      bool archive = RA::GetConfigStore()->GetConfigAsBool(configname, true);

      RA::Debug(LL_PER_CONNECTION,FN,
        "calling ServerSideKeyGen with userid =%s, archive=%s", userid, archive? "true":"false");

      RA::ServerSideKeyGen(session, cuid, userid,
                           channel->getDrmWrappedDESKey(), &pKey,
                           &wrappedPrivKey, &ivParam, drmconnid,
                           archive, keysize, isECC);

      if (pKey == NULL) {
        RA::Error(LL_PER_CONNECTION,FN,
          "Failed to generate key on server. Please check DRM.");
        RA::Debug(LL_PER_CONNECTION,FN,
          "ServerSideKeyGen called, pKey is NULL");
        status = STATUS_ERROR_MAC_ENROLL_PDU;

        PR_snprintf(audit_msg, 512, "ServerSideKeyGen called, failed to generate key on server");
        goto loser;
      } else {
        RA::Debug(LL_PER_CONNECTION,FN,
          "key value = %s", pKey);
      }


      if (wrappedPrivKey == NULL) {
        RA::Debug(LL_PER_CONNECTION,FN,
          "ServerSideKeyGen called, wrappedPrivKey is NULL");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "ServerSideKeyGen called, wrappedPrivKey is NULL");
        goto loser;
      } else {
        RA::Debug(LL_PER_CONNECTION,FN,
          "wrappedPrivKey = %s", wrappedPrivKey);
      }

      if (ivParam == NULL) {
        RA::Debug(LL_PER_CONNECTION,FN,
          "ServerSideKeyGen called, ivParam is NULL");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "ServerSideKeyGen called, ivParam is NULL");
        goto loser;
      } else
        RA::Debug(LL_PER_CONNECTION,FN, "ivParam = %s", ivParam);

      /*
       * the following code converts b64-encoded public key info into SECKEYPublicKey
       */
      SECStatus rv;
      SECItem der;
      CERTSubjectPublicKeyInfo* spki = NULL;
               
      if (isECC) {
          Buffer *decodePubKey = Util::URLDecode(pKey);
          char *pKey_ascii = NULL;
          if (decodePubKey != NULL) {
              pKey_ascii = 
                  BTOA_DataToAscii(decodePubKey->getBuf(), decodePubKey->size());
            
          } else {
              PR_snprintf(audit_msg, 512, "ServerSideKeyGen: failed to URL decode public key");
            goto loser;
          }

          der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
          rv = ATOB_ConvertAsciiToItem (&der, pKey_ascii);
      } else {
          der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
          rv = ATOB_ConvertAsciiToItem (&der, pKey);
      }

      if (rv != SECSuccess){
        RA::Debug(LL_PER_CONNECTION,FN,
          "failed to convert b64 public key to binary");
        SECITEM_FreeItem(&der, PR_FALSE);
        status = STATUS_ERROR_MAC_ENROLL_PDU;
          PR_snprintf(audit_msg, 512, "ServerSideKeyGen: failed to convert b64 public key to binary");
        goto loser;
      } else {
        RA::Debug(LL_PER_CONNECTION,FN,
          "decoded public key as: secitem (len=%d)",der.len);

        spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der);

        if (spki != NULL) {
          RA::Debug(LL_PER_CONNECTION,FN,
            "Successfully decoded DER SubjectPublicKeyInfo structure");
          pk_p = SECKEY_ExtractPublicKey(spki);
          if (pk_p != NULL)
            RA::Debug(LL_PER_CONNECTION,FN, "Successfully extracted public key from SPKI structure");
          else
            RA::Debug(LL_PER_CONNECTION,FN, "Failed to extract public key from SPKI");
        } else {
          RA::Debug(LL_PER_CONNECTION,FN,
            "Failed to decode SPKI structure");
        }

        SECITEM_FreeItem(&der, PR_FALSE);
            SECKEY_DestroySubjectPublicKeyInfo(spki);
      }

    } else { //generate keys on token

      RA::Debug(LL_PER_CONNECTION,FN,
                "Private key is to be generated on token");

      BYTE alg = 0x80;

      if(key_check && key_check->size())
         alg = 0x81;


      if (isECC) {
         alg = algorithm;
      }

      len = channel->StartEnrollment(
        se_p1, se_p2,
        wrapped_challenge,
        key_check,
        alg /* alg */, keysize,
        0x00 /* option */);

      RA::Debug(LL_PER_CONNECTION,FN,
          "channel->StartEnrollment returned length of public key blob: len=%d", len);

	StatusUpdate(session, extensions,
			start_progress + (index * progress_block_size) + 
			(progress_block_size * 45/100) /* progress */, 
			"PROGRESS_READ_PUBLIC_KEY");

      /* read the public key from buffer */
      if (len <= 0) {
	RA::Error(LL_PER_CONNECTION,FN,
		  "Error generating key on token.");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "Error generating key on token");
        goto loser;
      }

      RA::Debug(LL_PER_CONNECTION,FN,
		"Reading public key buffer from token");

      BYTE iobuf[4];
      iobuf[0] = 0xff;
      iobuf[1] = 0xff;
      iobuf[2] = 0xff;
      iobuf[3] = 0xff;
      /* use ReadObject to read IO buffer */
      public_key = channel->ReadObject(iobuf, 0, len);
      if (public_key == NULL) {
	RA::Error(LL_PER_CONNECTION,FN,
		  "Unable to read public key buffer from token");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "Unable to read public key buffer from token");
        goto loser;
      }
      RA::Debug(LL_PER_CONNECTION,FN,
	      "Successfully read public key buffer");
      
      RA::DebugBuffer(LL_PER_CONNECTION,FN,
		"public_key = ", public_key);

      //got public key blob
      // parse public key blob and check POP

      RA::Debug(LL_PER_CONNECTION,FN,
	      "challenge size=%d",plaintext_challenge->size());
      RA::DebugBuffer("RA_Enroll_Processor::process", "challenge = ", 
          plaintext_challenge);


      // We have received the public key blob for ECC

      // send status update to the client
	StatusUpdate(session, extensions,
			start_progress + (index * progress_block_size) + 
			(progress_block_size * 55/100) /* progress */, 
			"PROGRESS_PARSE_PUBLIC_KEY");

      RA::Debug(LL_PER_CONNECTION,FN,
		"About to Parse Public Key");

      pk_p = certEnroll->ParsePublicKeyBlob(
                (unsigned char *)(BYTE *)*public_key /*blob*/, 
                plaintext_challenge, isECC);

      if (pk_p == NULL) {
	    RA::Error(LL_PER_CONNECTION,FN,
		  "Failed to parse public key");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "Failed to parse public key");
        goto loser;
      }

    } //serverKeygen or not

    RA::Debug(LL_PER_CONNECTION,FN,
		"Keys generated. Proceeding with certificate enrollment");

    RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "success",
          "enrollment",
          applet_version != NULL ? applet_version : "",
          keyVersion != NULL? keyVersion : "",
          "keys generated");

    if(publisher_id != NULL)
    {
        ppEncodedPublicKeyInfo = &encodedPublicKeyInfo;

    }

    pretty_cuid = GetPrettyPrintCUID(cuid);

    nv.Add("pretty_cuid", pretty_cuid);
    nv.Add("cuid", cuid);
    nv.Add("msn", msn);
    nv.Add("userid", userid);
    nv.Add("profileId", profileId);

    /* populate auth parameters output to nv also */
    /* so we can reference to the auth parameter by */
    /* using $auth.cn$, or $auth.mail$ */
    if (login != NULL) {
      int s = login->Size();
      for (int x = 0; x < s; x++) {
         char namebuf[2048];
         char *name = login->GetNameAt(x);
         sprintf(namebuf, "auth.%s", name);
         nv.Add(namebuf, login->GetValue(name));
      }
    }

    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.cuid_label", 
		    OP_PREFIX, tokenType, keyType);

    RA::Debug(LL_PER_CONNECTION,FN,
		"Certificate label '%s'", configname);

    pattern = RA::GetConfigStore()->GetConfigAsString(configname, "$cuid$");
    cuid_label = MapPattern(&nv, (char *) pattern);

	StatusUpdate(session, extensions,
			start_progress + (index * progress_block_size) + 
			(progress_block_size * 60/100) /* progress */, 
			"PROGRESS_ENROLL_CERT");

    cert = certEnroll->EnrollCertificate(
                    pk_p, profileId, userid, cuid_label, 
		    connid, audit_msg, ppEncodedPublicKeyInfo);

    if (cert == NULL) {
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC_CERT_REQ, 
          userid, cuid, msn, "failure", "enrollment", applet_version, 
          keyVersion != NULL ? keyVersion : "", 
          "", connid,  audit_msg);
        goto loser;
    }

    if (!isECC) {
        si_mod = pk_p->u.rsa.modulus;
        modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);
    }

    /* 
     * RFC 3279
     * The keyIdentifier is composed of the 160-bit SHA-1 hash of the
     * value of the BIT STRING subjectPublicKey (excluding the tag,
     * length, and number of unused bits).
     */
	spkix = SECKEY_CreateSubjectPublicKeyInfo(pk_p);

    /* 
     * NSS magically multiply the length with 2^3 in cryptohi/seckey.c 
     * Hack: 
     */
    spkix->subjectPublicKey.len >>= 3;
    si_kid = PK11_MakeIDFromPubKey(&spkix->subjectPublicKey);
    spkix->subjectPublicKey.len <<= 3;

    keyid = new Buffer((BYTE*) si_kid->data, si_kid->len);

    if (!isECC) {
        si_exp = pk_p->u.rsa.publicExponent;
        exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);
        RA::Debug(LL_PER_CONNECTION,FN,
            "Keyid, modulus and exponent have been extracted from public key");
    }

    SECKEY_DestroySubjectPublicKeyInfo(spkix);

    cert_string = (char *) cert->string();
    certificates[index] = CERT_DecodeCertFromPackage((char *) cert_string, 
      (int) cert->size());
    if (certificates[index] != NULL) {
        RA::ra_tus_print_integer(cert_serial, &certificates[index]->serialNumber);
        RA::Debug("DoEnrollment", "Received Certificate");
        RA::Debug("DoEnrollment", cert_serial);

        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC_CERT_REQ, 
          userid, cuid, msn, "success", "enrollment", applet_version, 
          (keyVersion != NULL) ? keyVersion : "", cert_serial, connid,  "certificate received");
    }
    free(cert_string);
    ktypes[index] = PL_strdup(keyType);
    origins[index] = PL_strdup(cuid);

    if (serverKeygen) {
      //do PKCS#8

      BYTE objid[4];

      objid[0] = 0xFF;
      objid[1] = 0x00;
      objid[2] = 0xFF;
      objid[3] = 0xF3;

      BYTE keytype = 0x09; // RSAPKCS8Pair


      if( isECC) {
          keytype =  14 ; //ECCPKCS8Pair
      }

      Buffer priv_keyblob;
      /* url decode wrappedPrivKey */
      {
	Buffer *decodeKey = Util::URLDecode(wrappedPrivKey);
	// RA::DebugBuffer("cfu debug"," private key =",decodeKey);
	priv_keyblob =
	  Buffer(1, 0x01) + // encryption
	  Buffer(1, keytype)+ // keytype is RSAPKCS8Pair or ECCPKCS8Pair
	  Buffer(1,(BYTE)(keysize/256)) + // keysize is two bytes
	  Buffer(1,(BYTE)(keysize%256)) +
	  Buffer((BYTE*) *decodeKey, decodeKey->size());
	delete decodeKey;
      }

      //inject PKCS#8 private key
      BYTE perms[6];

      perms[0] = 0x40;
      perms[1] = 0x00;
      perms[2] = 0x40;
      perms[3] = 0x00;
      perms[4] = 0x40;
      perms[5] = 0x00;

      if (channel->CreateObject(objid, perms, priv_keyblob.size()) != 1) {
	status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "ServerSideKeyGen: store keys in token failed, channel create object error");
	goto loser;
      }


      if (channel->WriteObject(objid, (BYTE*)priv_keyblob, priv_keyblob.size()) != 1) {
	status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "ServerSideKeyGen: store keys in token failed, channel write object error");
	goto loser;
      }


      /* url decode the wrapped kek session key and keycheck*/
      Buffer data;
      {

	/*
	  RA::Debug(LL_PER_PDU, "", "getKekWrappedDESKey() returns =%s", channel->getKekWrappedDESKey());
	  RA::Debug(LL_PER_PDU, "", "getKeycheck() returns =%s", channel->getKeycheck());
	*/
	Buffer *decodeKey = Util::URLDecode(channel->getKekWrappedDESKey());

	/*
	  RA::Debug(LL_PER_PDU, "", "des key item len=%d",
	  decodeKey->size());
	  RA::DebugBuffer("cfu debug", "DES key =", decodeKey);
	*/
	char *keycheck = channel->getKeycheck();
	Buffer *decodeKeyCheck = Util::URLDecode(keycheck);
	if (keycheck)
	  PL_strfree(keycheck);

	/*
	  RA::Debug(LL_PER_PDU, "", "keycheck item len=%d",
	  decodeKeyCheck->size());
	  RA::DebugBuffer("cfu debug", "key check=", decodeKeyCheck);
	*/

	//XXX need randomize this later

	//	  BYTE iv[] = {0x01, 0x01,0x01,0x01,0x01,0x01,0x01,0x01};
	// get ivParam
	Buffer *iv_decoded = Util::URLDecode(ivParam);
	if (ivParam) {
	  PL_strfree(ivParam);
	}

        if(iv_decoded == NULL) {
           status = STATUS_ERROR_MAC_ENROLL_PDU;
           PR_snprintf(audit_msg, 512, "ServerSideKeyGen: store keys in token failed, iv data not found");
           delete decodeKey;
           delete decodeKeyCheck;
           goto loser; 
        }

        BYTE alg = 0x80;
        if(decodeKey && decodeKey->size()) {
            alg = 0x81;
        }

        Buffer eccPublicKeyData;
        if (isECC) {
            alg = algorithm;
            eccPublicKeyData = Buffer(1, pk_p->u.ec.publicValue.len) +
                Buffer((BYTE *) pk_p->u.ec.publicValue.data, pk_p->u.ec.publicValue.len);

                //RA::DebugBuffer("cfu debug", "ImportKeyEnc ecc public key data buffer =", &eccPublicKeyData);
        }

	data =
	  Buffer((BYTE*)objid, 4)+ // object id
	  Buffer(1,alg) +
	  Buffer(1, (BYTE) decodeKey->size()) + // 1 byte length
	  Buffer((BYTE *) *decodeKey, decodeKey->size())+ // key -encrypted to 3des block
	  // check size
	  // key check
	  Buffer(1, (BYTE) decodeKeyCheck->size()) + //keycheck size
	  Buffer((BYTE *) *decodeKeyCheck , decodeKeyCheck->size())+ // keycheck
	  Buffer(1, iv_decoded->size())+ // IV_Length
	  Buffer((BYTE*)*iv_decoded, iv_decoded->size()) ;

          if (isECC) {
              data = data + eccPublicKeyData;
          }
          delete iv_decoded;
	  //    RA::DebugBuffer("cfu debug", "ImportKeyEnc final data buffer =", &data);

	delete decodeKey;
	delete decodeKeyCheck;
      }

      if (channel->ImportKeyEnc(se_p1, se_p2, &data) != 1) {
	status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "ServerSideKeyGen: store keys in token failed, channel import key error");
	goto loser;
      }

      RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "success",
          "enrollment",
          applet_version != NULL ? applet_version : "",
          keyVersion != NULL? keyVersion : "",
          "server generated keys stored in token");


      /*
       * After keys are injected successfully, then write certificate object apdu
       * to token
       */

    } // serverKeygen


    StatusUpdate(session, extensions,
		 start_progress + (index * progress_block_size) + 
		 (progress_block_size * 70/100) /* progress */, 
		 "PROGRESS_PUBLISH_CERT");

    //Attempt publish if relevant
    if(ppEncodedPublicKeyInfo)
      { 

        publish_result = DoPublish(cuid,encodedPublicKeyInfo,cert,publisher_id,applet_version); 

      }

    if(ppEncodedPublicKeyInfo)
      {
	RA::Debug(LL_PER_CONNECTION,FN,
			"Deleting PublicKeyInfo object.");

	SECITEM_FreeItem(*ppEncodedPublicKeyInfo, PR_TRUE);
      }

    if(publish_result == 0)
      {
        status = STATUS_ERROR_PUBLISH;

        RA::Error(LL_PER_CONNECTION,FN,
		 "Enroll Certificate Publish Failure %d", status);

        RA::Debug(LL_PER_CONNECTION,FN,
		"Enroll Certificate Publish Failure %d",status);
        PR_snprintf(audit_msg, 512, "publish certificate error");
        goto loser;
      }

    if (cert != NULL) {
      RA::Debug(LL_PER_CONNECTION,FN,
		"Enroll Certificate Finished");
    } else {
      RA::Error(LL_PER_CONNECTION,FN,
	"Enroll Certificate Failure");

        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "cert is null");
        goto loser;
    }

	StatusUpdate(session, extensions,
			start_progress + (index * progress_block_size) + 
			(progress_block_size * 80/100) /* progress */, 
			"PROGRESS_IMPORT_CERT");

    /* write certificate from CA to netkey */
    if (pkcs11obj_enable) {
        ObjectSpec *objSpec = 
          ObjectSpec::ParseFromTokenData(
           (cert_id[0] << 24) +
           (cert_id[1] << 16),
           cert);
       pkcs_objx->AddObjectSpec(objSpec);
    } else {
        RA::Debug(LL_PER_CONNECTION,FN,
          "About to create certificate object on token");
        rc = channel->CreateCertificate(cert_id, cert);
        if (rc == -1) {
          RA::Error(LL_PER_CONNECTION,FN,
            "Failed to create certificate object on token");
          status = STATUS_ERROR_MAC_ENROLL_PDU;
            PR_snprintf(audit_msg, 512, "Failed to create certificate object on token");
          goto loser;
        }
    }

    // build label
    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label", 
      OP_PREFIX, tokenType, keyType);
    RA::Debug(LL_PER_CONNECTION,FN,
      "label '%s'", configname);
    pattern = RA::GetConfigStore()->GetConfigAsString(configname);
    label = MapPattern(&nv, (char *) pattern);

    if (pkcs11obj_enable) {
        Buffer b = channel->CreatePKCS11CertAttrsBuffer(
                        key_type, cert_attr_id, label, keyid);
        ObjectSpec *objSpec = 
                ObjectSpec::ParseFromTokenData(
                                (cert_attr_id[0] << 24) +
                                (cert_attr_id[1] << 16),
                                &b);
        pkcs_objx->AddObjectSpec(objSpec);
    } else {
        RA::Debug(LL_PER_CONNECTION,FN,
            "About to create PKCS#11 certificate Attributes");
        rc = channel->CreatePKCS11CertAttrs(key_type, cert_attr_id, label, keyid);
        if (rc == -1) {
            RA::Error(LL_PER_CONNECTION,FN,
                "PKCS11 Certificate attributes creation failed");
            status = STATUS_ERROR_MAC_ENROLL_PDU;
                PR_snprintf(audit_msg, 512, "PKCS11 Certificate attributes creation failed");
           goto loser;
        }
    }

    if (pkcs11obj_enable) {
        RA::Debug(LL_PER_CONNECTION,FN,
          "Create PKCS11 Private Key Attributes Buffer");

        Buffer b;
        if (!isECC) {
            b = channel->CreatePKCS11PriKeyAttrsBuffer(key_type,
                        pri_attr_id, label, keyid, modulus, OP_PREFIX,
                        tokenType, keyTypePrefix);

        } else { //isECC
            eccParams  =   &pk_p->u.ec.DEREncodedParams;
            b = channel->CreatePKCS11ECCPriKeyAttrsBuffer(key_type,     
                        pri_attr_id, label, keyid, eccParams, OP_PREFIX,
                        tokenType, keyTypePrefix);
        }
        ObjectSpec *objSpec = 
                ObjectSpec::ParseFromTokenData( 
                                (pri_attr_id[0] << 24) +
                                (pri_attr_id[1] << 16),
                                &b);
        pkcs_objx->AddObjectSpec(objSpec);
    } else {
    	RA::Debug(LL_PER_CONNECTION,FN,
		"Create PKCS11 Private Key Attributes");
    	rc = channel->CreatePKCS11PriKeyAttrs(key_type, pri_attr_id, label, keyid, modulus, OP_PREFIX, tokenType, keyTypePrefix);
    	if (rc == -1) {
        	RA::Error(LL_PER_CONNECTION,FN,
		"PKCS11 private key attributes creation failed");
        	status = STATUS_ERROR_MAC_ENROLL_PDU;
                PR_snprintf(audit_msg, 512, "PKCS11 private key attributes creation failed");
        	goto loser;
    	}
    }

    if (pkcs11obj_enable) {
        Buffer b;
        if (!isECC) {
            b = channel->CreatePKCS11PubKeyAttrsBuffer(key_type, 
                pub_attr_id, label, keyid, 
                exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
        } else {
            b = channel->CreatePKCS11ECCPubKeyAttrsBuffer(key_type,
                        pub_attr_id, label, keyid,&pk_p->u.ec, eccParams,
                        OP_PREFIX, tokenType, keyTypePrefix);
        }
        ObjectSpec *objSpec = 
            ObjectSpec::ParseFromTokenData(
               (pub_attr_id[0] << 24) +
               (pub_attr_id[1] << 16),
               &b);
        pkcs_objx->AddObjectSpec(objSpec);
    } else {
        RA::Debug(LL_PER_CONNECTION,FN,
            "Create PKCS11 Public Key Attributes");
        rc = channel->CreatePKCS11PubKeyAttrs(key_type, pub_attr_id, label, keyid, 
           exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
        if (rc == -1) {
            RA::Error(LL_PER_CONNECTION,FN,
                "PKCS11 public key attributes creation failed");
            status = STATUS_ERROR_MAC_ENROLL_PDU;
                PR_snprintf(audit_msg, 512, "PKCS11 public key attributes creation failed");
            goto loser;
        }
    }
    RA::Debug(LL_PER_CONNECTION,FN, "End of keygen/certificate enrollment");

    PR_snprintf(activity_msg, 4096, "certificate %s stored on token", cert_serial);
    RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
      userid != NULL ? userid : "",
      cuid != NULL ? cuid : "",
      msn != NULL ? msn : "",
      "success",
      "enrollment",
      applet_version != NULL ? applet_version : "",
      keyVersion != NULL? keyVersion : "",
      activity_msg);
 
   RA::tdb_activity(session->GetRemoteIP(), 
      (char *) cuid, 
      "enrollment", 
      "success", 
      activity_msg,
      userid != NULL? userid : "",
      tokenType);

loser:
    if (strlen(audit_msg) > 0) { // a failure occurred
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "failure",
          "enrollment",
          applet_version != NULL ? applet_version : "",
          keyVersion != NULL? keyVersion : "",
          audit_msg);

        if ((cuid != NULL) && (tokenType != NULL)) {
            RA::tdb_activity(session->GetRemoteIP(),
                (char *) cuid,
                "enrollment",
                "failure",
                audit_msg,
                userid != NULL? userid : "",
                tokenType);
        }
    }

    if( keyVersion != NULL ) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }

    if( modulus != NULL ) {
        delete modulus;
        modulus = NULL;
    }
    if( keyid != NULL ) {
        delete keyid;
        keyid = NULL;
    }
    if( exponent != NULL ) {
        delete exponent;
        exponent = NULL;
    }
    if( cert != NULL ) {
        delete cert;
        cert = NULL;
    }
    if( public_key != NULL ) {
        delete public_key;
        public_key = NULL;
    }
  
    if (pKey !=NULL)
        PR_Free(pKey);

    if (wrappedPrivKey !=NULL)
        PR_Free(wrappedPrivKey);

    if( si_kid != NULL ) {
        SECITEM_FreeItem( si_kid, PR_TRUE );
        si_kid = NULL;
    }
    if( certEnroll != NULL ) {
        delete certEnroll;
        certEnroll = NULL;
    }
    if( label != NULL ) {
        PL_strfree( (char *) label );
        label = NULL;
    }
    if( cuid_label != NULL ) {
        PL_strfree( (char *) cuid_label );
        cuid_label = NULL;
    }
    if( pretty_cuid != NULL ) {
        PR_Free( (char *) pretty_cuid );
        pretty_cuid = NULL;
    }
    if (pk_p != NULL) {
        if (serverKeygen) {
            RA::Debug(LL_PER_CONNECTION,FN,"DoEnrollment about to call SECKEY_DestroyPublicKey on pk_p");
            SECKEY_DestroyPublicKey(pk_p);
        } else {
            RA::Debug(LL_PER_CONNECTION,FN,"DoEnrollment about to call free on pk_p");
            free(pk_p);
        }

        pk_p = NULL;
    }
    return status;
}

SECStatus getRandomNumber(unsigned long *number) {
  SECStatus rv;

  if (number == NULL) {
    return SECFailure;
  }

  rv = PK11_GenerateRandom((unsigned char *) number, sizeof(unsigned long));
  return rv;
}


/**
 * @return true if successfull
 */
bool RA_Enroll_Processor::GetCardManagerAppletInfo(
    RA_Session *a_session,   /* in */
	Buffer *a_cardmanagerAID,  /* in */
    RA_Status &a_status,     /* out */
    char * &msn,             /* out */
    char * &cuid,            /* out */
    Buffer &token_cuid       /* out */
)
{
	bool r = true;  // result
    Buffer *cplc_data = NULL;
    Buffer token_msn;

    SelectApplet(a_session, 0x04, 0x00, a_cardmanagerAID);
    cplc_data = GetData(a_session);
    if (cplc_data == NULL) {
          RA::Error("RA_Enroll_Processor::Process", 
			"Get Data Failed");
          a_status = STATUS_ERROR_SECURE_CHANNEL;		 
		  r = false;
          goto loser;
    }
    RA::DebugBuffer("RA_Enroll_Processor::process", "CPLC Data = ", 
		    	cplc_data);
    if (cplc_data->size() < 47) {
          RA::Error("RA_Format_Processor::Process",
                        "Invalid CPLC Size");
          a_status = STATUS_ERROR_SECURE_CHANNEL;
		  r = false;
          goto loser;
    }
    token_cuid =  Buffer(cplc_data->substr(3,4)) + 
	     Buffer(cplc_data->substr(19,2)) + 
	     Buffer(cplc_data->substr(15,4));
    RA::DebugBuffer("RA_Enroll_Processor::process", "Token CUID= ", 
		    	&token_cuid);
    cuid = Util::Buffer2String(token_cuid);
    RA::Debug("RA_Enroll_Processor::process", "CUID(String)= '%s'", 
		    	cuid);
    token_msn = Buffer(cplc_data->substr(41, 4));
    RA::DebugBuffer("RA_Enroll_Processor::process", "Token MSN= ", 
		    	&token_msn);
    msn = Util::Buffer2String(token_msn);
    RA::Debug("RA_Enroll_Processor::process", "MSN(String)= '%s'", 
		    	msn);
	loser:
    if( cplc_data != NULL ) {
        delete cplc_data;
    }

	return r;
}

bool RA_Enroll_Processor::GetAppletInfo(
	RA_Session *a_session,   /* in */
    Buffer *a_aid ,  /* in */
    BYTE &o_major_version,
    BYTE &o_minor_version,
    BYTE &o_app_major_version,
    BYTE &o_app_minor_version)
{
    int total_mem = 0;
    int free_mem  = 0;
    Buffer *token_status = NULL;
    SelectApplet(a_session, 0x04, 0x00, a_aid);
    token_status = GetStatus(a_session, 0x00, 0x00);
    if (token_status == NULL) {
      o_major_version = 0x0;
      o_minor_version = 0x0;
      o_app_major_version = 0x0;
      o_app_minor_version = 0x0;
    } else {
      o_major_version = ((BYTE*)*token_status)[0];     // is this protocol version?
      o_minor_version = ((BYTE*)*token_status)[1];
      o_app_major_version = ((BYTE*)*token_status)[2]; // and this applet version?
      o_app_minor_version = ((BYTE*)*token_status)[3];

      BYTE tot_high = ((BYTE*)*token_status)[6];
      BYTE tot_low  = ((BYTE*)*token_status)[7];

      BYTE free_high = ((BYTE*)*token_status)[10];
      BYTE free_low  = ((BYTE*)*token_status)[11];

      total_mem =   (tot_high << 8)  + tot_low;
      free_mem  =   (free_high << 8) + free_low;

      totalAvailableMemory = total_mem;
      totalFreeMemory      = free_mem;

      RA::DebugBuffer("RA_Enroll_Processor::Process AppletInfo Data", "Data=", token_status);
      delete token_status;
    }
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	      "Major=%d Minor=%d Applet Major=%d Applet Minor=%d Total Mem %d Free Mem %d", 
			o_major_version, o_minor_version, o_app_major_version, o_app_minor_version,total_mem,free_mem);
	return true;
}


/**
 * Query applet for build ID info
 * 'Pretty'-print it into useful format, along with version info
 * example input:
 *  a_app_major_version = 1
 *  a_app_minor_version = 3
 * Examples for the following outputs:
 * o_av   = "1.3.45FC0218"
 * The caller is responsible for free'ing (o_av)
 */
bool RA_Enroll_Processor::FormatAppletVersionInfo(
    RA_Session *a_session,
	const char *a_tokenType,
	char *a_cuid,
    BYTE a_app_major_version,
    BYTE a_app_minor_version,
	RA_Status &o_status,            // out
	char * &o_av // out.  
)
{
	bool r=true;
	char configname[256];
	char *av=NULL;
	
	// retrieve the 4-byte applet ID from the token
	Buffer *tokenBuildID = GetAppletVersion(a_session);

	if (tokenBuildID == NULL) {
		// If there was no applet on the token
		PR_snprintf((char *)configname, 256, "%s.%s.update.applet.emptyToken.enable", OP_PREFIX,
				a_tokenType);
	// XXX checks if emptyToken is enabled. This should probably get moved
    // to the applet update function, and leave this fn only for getting
    // the version information
		if (!RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
			RA::Error("RA_Enroll_Processor::Process", 
					"no applet found and applet upgrade not enabled");
			o_status = STATUS_ERROR_SECURE_CHANNEL;  // XXX  incorrect error message
			r=false;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "secure channel not established", "", a_tokenType); // XXX incorrect error message
			goto loser;
		}
	} else {
		// if there was an applet on the token:
		char * bid_string =  Util::Buffer2String(*tokenBuildID);
		RA::Debug("RA_Enroll_Processor", "buildid = %s", bid_string);
		av = PR_smprintf( "%x.%x.%s", 
			a_app_major_version, a_app_minor_version, bid_string);
		PR_Free(bid_string);
	}
	o_av = (av == NULL) ? strdup("") : av;

	RA::Debug("RA_Enroll_Processor", "final_applet_version = %s", o_av);
loser:
	if( tokenBuildID != NULL ) {
		delete tokenBuildID;
	}
	return r;
}

/**
 * Checks if we need to upgrade applet. 
 * The version of the current token is passed IN to this function
 * in o_current_applet_on_token. If the applet is upgraded, this
 * out parameter will be set to the new applet version id.
 * maj/minor versions will be also updated if the applet was updated.
 */
bool RA_Enroll_Processor::CheckAndUpgradeApplet(
		RA_Session *a_session,
		NameValueSet *a_extensions,
		char *a_cuid,
		const char *a_tokenType,
		char *&o_current_applet_on_token,
		BYTE &o_major_version,
		BYTE &o_minor_version,
		Buffer *a_aid,
                const char *a_msn, 
                const char *a_userid,
		RA_Status &o_status, 
                char **keyVersion )
{
        int rc = 0;
	const char *FN = "RA_Enroll_Processor::CheckAndUpgradeApplet";
	bool r = true;
	const char *applet_dir=NULL;
    const char *connid = NULL;
    Buffer *token_status = NULL;
	char configname[256];

	// You specify the following parameters to get applet upgrade working
	// *.update.applet.enable=true
	// *.update.applet.requiredVersion=maj.min.xxxxxxxx
	PR_snprintf((char *)configname, 256, "%s.%s.update.applet.encryption", OP_PREFIX, a_tokenType);
	SecurityLevel security_level = SECURE_MSG_MAC;
	if (RA::GetConfigStore()->GetConfigAsBool(configname, true))
			security_level = SECURE_MSG_MAC_ENC;

    PR_snprintf((char *)configname, 256, "%s.%s.update.applet.enable", OP_PREFIX, a_tokenType);
	if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
		PR_snprintf((char *)configname, 256, "%s.%s.update.applet.requiredVersion", OP_PREFIX, a_tokenType);
                g_applet_target_version = RA::GetConfigStore()->GetConfigAsString(configname);
		if (g_applet_target_version == NULL) {
			RA::Error(FN, "upgrade.version not found");
			o_status = STATUS_ERROR_MISCONFIGURATION;		 
			r = false;
			goto loser;
		}
		/* Bugscape #55826: used case-insensitive check below */
		if (PL_strcasecmp(g_applet_target_version, o_current_applet_on_token) != 0) {
			RA::Debug(LL_PER_CONNECTION, FN, "tokenType=%s before updating applet", a_tokenType);
			/* upgrade applet */
			PR_snprintf((char *)configname, 256, "%s.%s.update.applet.directory", OP_PREFIX, a_tokenType);
			applet_dir = RA::GetConfigStore()->GetConfigAsString(configname);
			if (applet_dir == NULL || strlen(applet_dir) == 0) {
				RA::Error(LL_PER_CONNECTION, FN,
						"Failed to read applet directory parameter %s", configname);
				o_status = STATUS_ERROR_MISCONFIGURATION;		 
				r = false;
				goto loser;
			}
			PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, a_tokenType);
			connid = RA::GetConfigStore()->GetConfigAsString(configname);
			RA::Debug(FN, "TKS connection id =%s", connid);
			//StatusUpdate(a_session, a_extensions, 5, "PROGRESS_UPGRADE_APPLET");

			if (rc = UpgradeApplet(a_session, (char *) OP_PREFIX, (char*) a_tokenType,
				o_major_version, o_minor_version, 
				g_applet_target_version, 
				applet_dir, security_level, 
				connid, a_extensions, 
				5, 
				12, 
                                keyVersion) != 1) {

				RA::Debug(FN, "applet upgrade failed");
				/**
				 * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
				 */
				SelectApplet(a_session, 0x04, 0x00, a_aid);
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "applet upgrade error", "", a_tokenType);
				o_status = STATUS_ERROR_UPGRADE_APPLET;		 
				r = false;

                                if (rc == -1) {
                                    RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                                        a_userid, a_cuid, a_msn, "Failure", "enrollment",
                                        *keyVersion != NULL? *keyVersion : "", o_current_applet_on_token, g_applet_target_version, "failed to setup secure channel");
                                } else {

                                    RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                                    a_userid, a_cuid, a_msn, "Success", "enrollment",
                                    *keyVersion != NULL? *keyVersion : "", o_current_applet_on_token, g_applet_target_version, "setup secure channel");
                                }


                                RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                                  a_userid, a_cuid, a_msn, "Failure", "enrollment",
                                  *keyVersion != NULL? *keyVersion : "",
                                  o_current_applet_on_token, g_applet_target_version,
                                  "applet upgrade");
                                
				goto loser;
			} else {
				// there may be a better place to do this, but worth testing here
				// RA::tdb_update(a_cuid, g_applet_target_version);
			}

			// Upgrade Applet reported success
			
                        RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                            a_userid, a_cuid, a_msn, "Success", "enrollment",
                            *keyVersion != NULL? *keyVersion : "", o_current_applet_on_token, g_applet_target_version, "setup secure channel");

                        RA::Audit(EV_APPLET_UPGRADE, AUDIT_MSG_APPLET_UPGRADE,
                          a_userid, a_cuid, a_msn, "Success", "enrollment",
                          *keyVersion != NULL? *keyVersion : "",
                          o_current_applet_on_token, g_applet_target_version, 
                          "applet upgrade");

			o_current_applet_on_token = strdup(g_applet_target_version);

			token_status = GetStatus(a_session, 0x00, 0x00);
			if (token_status == NULL) {
				RA::Error(FN, "Get Status Failed");
				o_status = STATUS_ERROR_SECURE_CHANNEL;		 // XXX
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "secure channel error", "", a_tokenType);
				r = false;
				goto loser;
			}

			o_major_version = ((BYTE*)*token_status)[2]; // applet version
			o_minor_version = ((BYTE*)*token_status)[3]; // not protocol version
loser:
    		if( token_status != NULL ) {
        		delete token_status;
    		}
		}
	} else {
        RA::Debug(FN, "Applet Upgrade has been disabled.");
    }
	return r;
}

/**
 * Authenticate user with LDAP plugin
 * @return true if authentication was successful
 */
bool RA_Enroll_Processor::AuthenticateUserLDAP(
		RA_Session *a_session,
                NameValueSet *a_extensions,
		char *a_cuid,
		AuthenticationEntry *a_auth,
		AuthParams *&login,
		RA_Status &o_status,
                const char *a_token_type
)
{
	const char *FN = "RA_Enroll_Processor::AuthenticateUserLDAP";
	int retry_limit = a_auth->GetAuthentication()->GetNumOfRetries();
	int retries = 0;
	int rc;
	bool r=false;

	RA::Debug(LL_PER_PDU, FN, "LDAP_Authentication is invoked.");
	rc = a_auth->GetAuthentication()->Authenticate(login);

	RA::Debug(FN, "Authenticate returned: %d", rc);

	// rc: (0:login correct) (-1:LDAP error)  (-2:User not found) (-3:Password error)

	// XXX replace with proper enums
	// XXX evaluate rc==0 as specific case - this is success, it shouldn't be the default

	while ((rc == TPS_AUTH_ERROR_USERNOTFOUND || 
			rc == TPS_AUTH_ERROR_PASSWORDINCORRECT ) 
				&& (retries < retry_limit)) {
		login = RequestLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */);
		retries++;
        if (login != NULL)
		    rc = a_auth->GetAuthentication()->Authenticate(login);
	}

	switch (rc) {
	case TPS_AUTH_OK:
		RA::Debug(LL_PER_PDU, FN, "Authentication successful.");
		r=true;
		break;
	case TPS_AUTH_ERROR_LDAP:
		RA::Error(FN, "Authentication failed. LDAP Error");
		o_status = STATUS_ERROR_LDAP_CONN;
		RA::Debug(LL_PER_PDU, FN, "Authentication status=%d rc=%d", o_status,rc);
		RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication error", "", a_token_type);
		r = false;
		break;
	case TPS_AUTH_ERROR_USERNOTFOUND:
		RA::Error(FN, "Authentication failed. User not found");
		o_status = STATUS_ERROR_LOGIN;
		RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication error",  "", a_token_type);
		r = false;
		break;
	case TPS_AUTH_ERROR_PASSWORDINCORRECT:
		RA::Error(FN, "Authentication failed. Password Incorrect");
		o_status = STATUS_ERROR_LOGIN;
		RA::Debug(LL_PER_PDU, FN, "Authentication status=%d rc=%d", o_status,rc);
		RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication error", "", a_token_type);
		r = false;
		break;
	default:
		RA::Error(FN, "Undefined LDAP Auth Error.");
		r = false;
		break;
	}

	return r;
}

/**
 * Request Login info and user id from user, if necessary
 * This call will allocate a new Login structure,
 * and a char* for the user id. The caller is responsible
 * for freeing this memory
 * @return true of success, false if failure
 */
bool RA_Enroll_Processor::RequestUserId(
			RA_Session * a_session,
                        NameValueSet *a_extensions,
			const char * a_configname, 
			const char * a_tokenType, 
			char *a_cuid,
			AuthParams *& o_login, const char *&o_userid, RA_Status &o_status) 
{

	if (RA::GetConfigStore()->GetConfigAsBool(a_configname, 1)) {
		if (a_extensions != NULL && 
		    a_extensions->GetValue("extendedLoginRequest") != NULL) 
                {
                   // XXX - extendedLoginRequest
                   RA::Debug("RA_Enroll_Processor::RequestUserId",
				"Extended Login Request detected");
                   AuthenticationEntry *entry = GetAuthenticationEntry(
			OP_PREFIX, a_configname, a_tokenType);
                   char **params = NULL;
                   char pb[1024];
                   char *locale = NULL;
		   if (a_extensions != NULL && 
		       a_extensions->GetValue("locale") != NULL) 
                   {
                           locale = a_extensions->GetValue("locale");
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
                             entry->GetAuthentication()->GetParamDescription(i, locale),
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
		   o_login = RequestExtendedLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */, params, n, title, description);

                   if (params != NULL) {
                       for (int nn=0; nn < n; nn++) {
                           if (params[nn] != NULL) {
                               PL_strfree(params[nn]);
                               params[nn] = NULL;
                           }
                       }
                       free(params);
                       params = NULL;
                   }

                   if (title != NULL) {
                       PL_strfree(title);
                       title = NULL;
                   }

                   if (description != NULL) {
                       PL_strfree(description);
                       description = NULL;
                   }

		  if (o_login == NULL) {
			RA::Error("RA_Enroll_Processor::Process", 
					"login not provided");
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, 
					"enrollment", "failure", "login not found", "", a_tokenType);
			return false;
		  }

                   RA::Debug("RA_Enroll_Processor::RequestUserId",
	"Extended Login Request detected calling RequestExtendedLogin() login=%x", o_login);
		  o_userid = PL_strdup( o_login->GetUID() );
		  RA::Debug("RA_Enroll_Processor::Process", 
				"userid = '%s'", o_userid);
                } else {
		  o_login = RequestLogin(a_session, 0 /* invalid_pw */, 0 /* blocked */);
		  if (o_login == NULL) {
			RA::Error("RA_Enroll_Processor::Process", 
					"login not provided");
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, 
					"enrollment", "failure", "login not found", o_userid, a_tokenType);
			return false;
		  }
		  o_userid = PL_strdup( o_login->GetUID() );
		  RA::Debug("RA_Enroll_Processor::Process", 
				"userid = '%s'", o_userid);
                }
	}
	return true;
}

/**
 *  Authenticate the user with the configured authentication plugin
 * @return true if authentication successful
 */

bool RA_Enroll_Processor::AuthenticateUser(
			RA_Session * a_session,
			const char * a_configname, 
			char *a_cuid,
			NameValueSet *a_extensions,
			const char *a_tokenType,
			AuthParams *& a_login, const char *&o_userid, RA_Status &o_status
			)
{
	bool r=false;

	RA::Debug("RA_Enroll_Processor::AuthenticateUser", "started");
	if (RA::GetConfigStore()->GetConfigAsBool(a_configname, false)) {
		if (a_login == NULL) {
			RA::Error("RA_Enroll_Processor::AuthenticateUser", "Login Request Disabled. Authentication failed.");
			o_status = STATUS_ERROR_LOGIN;
			goto loser;
		}

		RA::Debug("RA_Enroll_Processor::AuthenticateUser",
				"Authentication enabled");
		char configname[256];
		PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, a_tokenType);
		const char *authid = RA::GetConfigStore()->GetConfigAsString(configname);
		if (authid == NULL) {
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "login not found", "", a_tokenType);
			goto loser;
		}
		AuthenticationEntry *auth = RA::GetAuth(authid);

		if (auth == NULL) {
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication error", "", a_tokenType);
			goto loser;
		}

		StatusUpdate(a_session, a_extensions, 2, "PROGRESS_START_AUTHENTICATION");

		char *type = auth->GetType();
		if (type == NULL) {
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication is missing param type", "", a_tokenType);
			r = false;
			goto loser;
		}

		if (strcmp(type, "LDAP_Authentication") == 0) {
	                RA::Debug("RA_Enroll_Processor::AuthenticateUser", "LDAP started");
			r = AuthenticateUserLDAP(a_session, a_extensions, a_cuid, auth, a_login, o_status, a_tokenType);
			o_status = STATUS_ERROR_LOGIN;
			goto loser;
		} else {
			RA::Error("RA_Enroll_Processor::AuthenticateUser", "No Authentication type was found.");
			o_status = STATUS_ERROR_LOGIN;
			RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "authentication error", "", a_tokenType);
			r = false;
			goto loser;
		}
	} else {
		r = true;
		RA::Debug("RA_Enroll_Processor::AuthenticateUser",
				"Authentication has been disabled.");
	}
	loser:
		return r;
}




    /**
     * Checks if the token has the required key version.
	 * If not, we can swap out the keys on the token with another
     * set of keys
     */

/* XXX AID's should be member variables */
bool RA_Enroll_Processor::CheckAndUpgradeSymKeys(
	//RA_Session * a_session,
	//NameValueSet *a_extensions,
	//const char * a_configname, 
	//char *a_cuid,
	RA_Session *a_session,
	NameValueSet* a_extensions,
	char *a_cuid,
	const char *a_tokenType,
	char *a_msn,
        const char *a_applet_version,
        const char *a_userid,
        const char *a_key_version,
	Buffer *a_cardmanagerAID,  /* in */
	Buffer *a_appletAID,       /* in */
    Secure_Channel *&o_channel,  /* out */
	RA_Status &o_status          /* out */
	)
{
	char *FN = ( char * ) "RA_EnrollProcessor::CheckAndUpgradeSymKeys";
	char configname[256];
	const char *connid = NULL;
	const char *tksid = NULL;
	int rc;
	bool r = false;
	Buffer key_data_set;
        char audit_msg[512] = "";
        char curVer[10];
        char newVer[10];

        char *curKeyInfoStr = NULL;
        char *newVersionStr = NULL;

	// the TKS is responsible for doing much of the symmetric keys update
	// so lets find which TKS we're talking about TKS now.
	PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, a_tokenType);
	tksid = RA::GetConfigStore()->GetConfigAsString(configname);

	PR_snprintf((char *)configname, 256,"%s.%s.update.symmetricKeys.enable", OP_PREFIX, a_tokenType);

	RA::Debug(FN, "Symmetric Keys %s", configname);

	if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {

		RA::Debug(LL_PER_CONNECTION, FN, 
			"tokenType=%s configured to update symmetric keys", a_tokenType);

		// the requiredVersion config parameter indicates what key version
		// the token should have before further operations. If the token
		// has an older version, we try to change it.
		PR_snprintf((char *)configname, 256, 
			"%s.%s.update.symmetricKeys.requiredVersion", OP_PREFIX, a_tokenType);

		int requiredV = RA::GetConfigStore()->GetConfigAsInt(configname, 0x00);

		// If there was a secure channel set up, let's clear it out
		if( o_channel != NULL ) {
			delete o_channel;
			o_channel = NULL;
		}
		// try to make a secure channel with the 'requiredVersion' keys
		// If this fails, we know we will have to attempt an upgrade
		// of the keys
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
		o_channel = SetupSecureChannel(a_session, 
				requiredV,
				defKeyIndex  /* default key index */, tksid);

		// If that failed, we need to find out what version of keys 
		// are on the token
		if (o_channel != NULL) {
          r = true;
        } else {
			/**
			 * Select Card Manager for Put Key operation.
			 */
			SelectApplet(a_session, 0x04, 0x00, a_cardmanagerAID);
			/* if the key of the required version is
			 * not found, create them.
			 */ 
			//  This sends a InitializeUpdate request to the token.
			//  We tell the token to use whatever it thinks is the
			//  default key version (0). It will return the version
			//  of the key it actually used later. (This is accessed
			//  with GetKeyInfoData below)
			//  [ Note: This is not explained very well in the manual
			//    The token can have multiple sets of symmetric keys
			//    Each set is given a version number, which I think is
			//    better thought of as a SLOT. One key slot is populated
			//    with a set of keys when the token is manufactured.
			//    This is then designated as the default key set version.
			//    Later, we will write a new key set with PutKey, and
			//    set it to be the new default]
        PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
        int defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
			o_channel = SetupSecureChannel(a_session, 
					defKeyVer,  /* default key version */
					defKeyIndex  /* default key index */, tksid);

			if (o_channel == NULL) {
                                PR_snprintf(audit_msg, 512, "enrollment processing, failed to create secure channel"); 

				RA::Error(FN, "failed to establish secure channel");
				o_status = STATUS_ERROR_SECURE_CHANNEL;		 
				goto loser;
			}

			/* Complete the secure channel handshake */
			/* XXX need real enumeration of error codes here */
			rc = o_channel->ExternalAuthenticate();
			if (rc != 1) {
				RA::Error(FN, "External authentication in secure channel failed");
				o_status = STATUS_ERROR_EXTERNAL_AUTH;
				/* XXX should print out error codes */
                                PR_snprintf(audit_msg, 512, "enrollment processing, external authentication error"); 
				goto loser;
			}

			// Assemble the Buffer with the version information
			// The second byte is the key offset, which is always 1
			BYTE nv[2] = { requiredV, 0x01 };
			Buffer newVersion(nv, 2);

			// GetKeyInfoData will return a buffer which is bytes 11,12 of
			// the data structure on page 89 of Cyberflex Access Programmer's
			// Guide
			// Byte 0 is the key set version.
			// Byte 1 is the index into that key set
			Buffer curKeyInfo = o_channel->GetKeyInfoData();


			// This code makes a call to the TKS to get a new key set for
			// the token. The new key set data is written to the Buffer
			// key_data_set.
			PR_snprintf((char *)configname, 256,"%s.%s.tks.conn", OP_PREFIX, a_tokenType);
			connid = RA::GetConfigStore()->GetConfigAsString(configname);

			rc = CreateKeySetData(
					o_channel->GetKeyDiversificationData(), 
					curKeyInfo,
					newVersion,
					key_data_set, connid);
			if (rc != 1) {
				RA::Error(FN, "failed to create new key set");
				o_status = STATUS_ERROR_CREATE_CARDMGR;
                                PR_snprintf(audit_msg, 512, "enrollment processing, create card key error"); 
				goto loser;
			}

			StatusUpdate(a_session, a_extensions, 13, "PROGRESS_PUT_KEY");

			// sends a PutKey PDU with the new key set to change the
			// keys on the token
			BYTE curVersion = ((BYTE*)curKeyInfo)[0];
			BYTE curIndex = ((BYTE*)curKeyInfo)[1];
			rc = o_channel->PutKeys(a_session, 
					curVersion, 
					curIndex,
					&key_data_set);


                        curKeyInfoStr = Util::Buffer2String(curKeyInfo);
                        newVersionStr = Util::Buffer2String(newVersion);

                        if(curKeyInfoStr != NULL && strlen(curKeyInfoStr) >= 2) {
                            curVer[0] = curKeyInfoStr[0]; curVer[1] = curKeyInfoStr[1]; curVer[2] = 0;
                        }
                        else {
                            curVer[0] = 0;
                        }

                        if(newVersionStr != NULL && strlen(newVersionStr) >= 2) {
                            newVer[0] = newVersionStr[0] ; newVer[1] = newVersionStr[1] ; newVer[2] = 0;
                        }
                        else {
                            newVer[0] = 0;
                        }


                        if (rc!=0) {
                            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                              a_userid != NULL ? a_userid : "", a_cuid != NULL ? a_cuid : "",  a_msn != NULL ? a_msn : "", "Failure", "enrollment",
                              a_applet_version != NULL ? a_applet_version : "", curVer, newVer,
                              "key changeover");

                            if ((a_cuid != NULL) && (a_tokenType != NULL)) {
                                RA::tdb_activity(a_session->GetRemoteIP(),
                                    a_cuid,
                                    "enrollment",
                                    "failure",
                                    "key changeover failed",
                                    a_userid != NULL? a_userid : "",
                                    a_tokenType);
                            }
                            goto loser;
                        } else {
                            RA::Audit(EV_KEY_CHANGEOVER, AUDIT_MSG_KEY_CHANGEOVER,
                              a_userid != NULL ? a_userid : "", a_cuid != NULL ? a_cuid : "", a_msn != NULL ? a_msn : "", "Success", "enrollment",
                              a_applet_version != NULL ? a_applet_version : "", curVer, newVer,
                              "key changeover");
                        }

			/**
			 * Re-select the Applet.
			 */
			SelectApplet(a_session, 0x04, 0x00, a_appletAID);
			if( o_channel != NULL ) {
				delete o_channel;
				o_channel = NULL;
			}

			// Make a new secure channel with the new symmetric keys
			o_channel = SetupSecureChannel(a_session, requiredV,
					defKeyIndex  /* default key index */, tksid);
			if (o_channel == NULL) {
				RA::Error(FN, "failed to establish secure channel after reselect");
				o_status = STATUS_ERROR_CREATE_CARDMGR;
                                PR_snprintf(audit_msg, 512, "enrollment processing, secure channel setup error after reselect"); 
				goto loser;
			} else {
				RA::Debug(FN, "Key Upgrade has completed successfully.");
				r = true;  // Success!!

                                RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
                                  a_userid != NULL ? a_userid : "", a_cuid != NULL ? a_cuid : "", 
                                  a_msn != NULL ? a_msn : "", "success", "enrollment", a_applet_version != NULL ? a_applet_version : "",
                                  newVer, "enrollment processing, key upgrade completed");
			}

		}
	} else {

		RA::Debug(FN, "Key Upgrade has been disabled.");

		if( o_channel != NULL ) {
			delete o_channel;
			o_channel = NULL;
		}
        PR_snprintf((char *)configname, 256,"channel.defKeyVersion");
        int defKeyVer = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
        PR_snprintf((char *)configname, 256,"channel.defKeyIndex");
        int defKeyIndex = RA::GetConfigStore()->GetConfigAsInt(configname, 0x0);
		o_channel = SetupSecureChannel(a_session, 
				defKeyVer,
				defKeyIndex  /* default key index */, tksid);
		r = true;	  // Sucess!!
                RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
                  a_userid, a_cuid, a_msn, "success", "enrollment", a_applet_version, 
                  a_key_version != NULL? a_key_version: "", 
                  "enrollment processing, key upgrade disabled");
	}
loser:
    
    if (curKeyInfoStr != NULL) {
        PR_Free( (char *) curKeyInfoStr);
        curKeyInfoStr = NULL;
    }

    if (newVersionStr != NULL) {
        PR_Free( (char *) newVersionStr);
        newVersionStr = NULL;
    }

    if (strlen(audit_msg) > 0) { // a failure occurred
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          a_userid != NULL ? a_userid : "",
          a_cuid != NULL ? a_cuid : "",
          a_msn != NULL ? a_msn : "",
          "failure",
          "enrollment",
          a_applet_version != NULL ? a_applet_version : "",
          a_key_version != NULL? a_key_version : "", 
          audit_msg);

        if ((a_cuid != NULL) && (a_tokenType != NULL)) {
            RA::tdb_activity(a_session->GetRemoteIP(),
                a_cuid,
                "enrollment",
                "failure",
                audit_msg,
                a_userid != NULL? a_userid : "",
                a_tokenType);
        }
    }

    return r;
}

/**
 * Processes the current session.
 */
TPS_PUBLIC RA_Status RA_Enroll_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    char *FN = ( char * ) "RA_Enroll_Processor::Process";
    char configname[256];
    char *cuid = NULL;
    char *msn = NULL;
    PRIntervalTime start, end;
    RA_Status status = STATUS_NO_ERROR;
    int rc = -1;
    Secure_Channel *channel = NULL;
    Buffer kdd;
    AuthParams *login = NULL;
    char *new_pin = NULL;
#define PLAINTEXT_CHALLENGE_SIZE 16
#define WRAPPED_CHALLENGE_SIZE 16
    Buffer *plaintext_challenge = 
        new Buffer(PLAINTEXT_CHALLENGE_SIZE, (BYTE)0);
    Buffer *wrapped_challenge = new Buffer(WRAPPED_CHALLENGE_SIZE, (BYTE)0);
    Buffer *key_check = new Buffer(0, (BYTE)0);
    const char *tokenType = NULL;

    //SecurityLevel security_level = SECURE_MSG_MAC_ENC;
    BYTE major_version = 0x0;
    BYTE minor_version = 0x0;
    BYTE app_major_version = 0x0;
    BYTE app_minor_version = 0x0;
    int isPinPresent = 0;
    Buffer *object = NULL;
    int seq = 0x00;
    unsigned long lastFormatVersion = 0x00;
    unsigned long lastObjectVersion = 0x00;
    int foundLastObjectVersion = 0;
    int pkcs11obj_enable = 0;
    int compress = 0;
    NameValueSet nv;
    int o_certNums = 0;

    CertEnroll *certEnroll = NULL;

    Buffer *token_status = NULL;
    char* appletVersion = NULL;
    char *final_applet_version = NULL;

    char *keyVersion = PL_strdup( "" );
    const char *userid = PL_strdup( "" );
    char *token_state = PL_strdup("inactive");
    char *khex = NULL;

    Buffer host_challenge = Buffer(8, (BYTE)0);
    Buffer key_diversification_data;
    Buffer key_info_data;
    Buffer card_challenge;
    Buffer card_cryptogram;
    const char *connid = NULL;
    const char *tksid = NULL;
    const char *authid = NULL;
    PKCS11Obj *pkcs11objx = NULL;
    Buffer labelBuffer;
    char activity_msg[4096];
    char audit_msg[512] = ""; 

    Buffer *CardManagerAID = RA::GetConfigStore()->GetConfigAsBuffer(
		   RA::CFG_APPLET_CARDMGR_INSTANCE_AID, 
		   RA::CFG_DEF_CARDMGR_INSTANCE_AID);
    Buffer *NetKeyAID = RA::GetConfigStore()->GetConfigAsBuffer(
		    RA::CFG_APPLET_NETKEY_INSTANCE_AID, 
		    RA::CFG_DEF_NETKEY_INSTANCE_AID);
    Buffer token_cuid;
    int maxRetries = 3;
    const char *pattern = NULL;
    char *label = NULL;
    CERTCertificate **certificates = NULL;
    char **ktypes = NULL;
    char **origins = NULL;
    char **tokenTypes = NULL;
    char *tokentype = NULL;
    char *profile_state = NULL;
	RA_Status st;
    bool renewed = false;
    bool do_force_format = false;

    RA::Debug("RA_Enroll_Processor::Process", "Client %s", 
                      session->GetRemoteIP());
    RA::Debug(LL_PER_PDU, FN, "Begin enroll process");

    // XXX need to validate all user input (convert to 'string' types)
    // to ensure that no buffer overruns
    start = PR_IntervalNow();

    /* Get the card serial number */
    if (!GetCardManagerAppletInfo(session, CardManagerAID, st, msn, cuid, token_cuid)) goto loser;

    /* Get the applet version information */
    if (!GetAppletInfo(session, NetKeyAID, 
        /*by ref*/ major_version, minor_version, 
        app_major_version, app_minor_version )) goto loser;

    if (!GetTokenType(OP_PREFIX, major_version, minor_version, 
            cuid, msn, extensions,
            status, tokenType)) { /* last two are 'out' params */
        /* ADE figure out what to do here for this line*/
        // RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "token type not found", "");
        goto loser;
    }

    // check if profile is enabled here
    PR_snprintf((char *)configname, 256, "config.Profiles.%s.state", tokenType);
    profile_state = (char *) RA::GetConfigStore()->GetConfigAsString(configname);
    if ((profile_state != NULL) && (PL_strcmp(profile_state, "Enabled") != 0)) {
         RA::Error(FN, "Profile %s Disabled for CUID %s", tokenType, cuid);
         status =  STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
         PR_snprintf(audit_msg, 512, "profile %s disabled", tokenType);
         goto loser;
    }

    if (RA::ra_is_token_present(cuid)) {

        int token_status = RA::ra_get_token_status(cuid);

         // As far as the ui states, state "enrolled" maps to the state of "FOUND" or 4;

         RA::Debug(FN, "Found token %s status %d", cuid, token_status);

        int STATUS_FOUND = 4;
        if (token_status == -1 || !RA::transition_allowed(token_status, STATUS_FOUND)) {
            RA::Error(FN, "Operation for CUID %s Disabled illegal transition attempted %d:%d", cuid,token_status, STATUS_FOUND);
            status = STATUS_ERROR_DISABLED_TOKEN;

            PR_snprintf(audit_msg, 512, "Operation for CUID %s Disabled, illegal transition attempted %d:%d.", cuid,token_status, STATUS_FOUND);
            goto loser;
        }

        // at this point, token is either active or uninitialized (formatted)
        // or the adminstrator has called for a force format.

        do_force_format = RA::ra_force_token_format(cuid);

        RA::Debug("RA_Enroll_Processor::Process","force format flag %d", do_force_format);

        if (!RA::ra_allow_token_reenroll(cuid) &&
            !RA::ra_allow_token_renew(cuid) &&
            !do_force_format) {
            RA::Error(FN, "CUID %s Re-Enrolled Disallowed", cuid);
            status = STATUS_ERROR_DISABLED_TOKEN;
            PR_snprintf(audit_msg, 512, "token re-enrollment or renewal disallowed");
            goto loser;
        }
    } else {
        RA::Debug(FN, "Not Found token %s", cuid);
        // This is a new token. We need to check our policy to see
        // if we should allow enrollment. raidzilla #57414
        PR_snprintf((char *)configname, 256, "%s.allowUnknownToken", 
            OP_PREFIX);
        if (!RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
            RA::Error(FN, "CUID %s Enroll Unknown Token", cuid);
            status = STATUS_ERROR_DISABLED_TOKEN;
            PR_snprintf(audit_msg, 512, "unknown token disallowed");
            goto loser;
        }
    }

    RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "enrollment",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "token enabled");


    /* XXX - this comment does not belong here
     *
     * This is very risky to call initialize and then
     * external authenticate later on.
     * The token will be locked if no external authenticate
     * follows the initialize update.
     */

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", 
		    OP_PREFIX, tokenType);
    tksid = RA::GetConfigStore()->GetConfigAsString(configname);
    if (tksid == NULL) {
        RA::Error(FN, "TKS Connection Parameter %s Not Found", configname);
        status = STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "token type TKS connection parameter not found");
        goto loser;
    }

	/* figure some more information about the applet version */
	/* XXX should probably move this further down, since the results
       of this function aren't used til much later */
	if (!FormatAppletVersionInfo(session, tokenType, cuid,
		app_major_version, app_minor_version,
		status,
		final_applet_version /*out */)) { 
            PR_snprintf(audit_msg, 512, "FormatAppletVersionInfo error");
            goto loser;
        }

	PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);
	if (!RequestUserId(session, extensions, configname, tokenType, cuid, login, userid, status)){
                PR_snprintf(audit_msg, 512, "RequestUserId error");
		goto loser;
	}
    
    PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);

	if (!AuthenticateUser(session, configname, cuid, extensions, 
				tokenType, login, userid, status)){
                PR_snprintf(audit_msg, 512, "AuthenticateUser error");
		goto loser;
	}

    RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "enrollment",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "token login successful");

        // get authid for audit log
        PR_snprintf((char *)configname, 256, "%s.%s.auth.id", OP_PREFIX, tokenType);
        authid = RA::GetConfigStore()->GetConfigAsString(configname);

	StatusUpdate(session, extensions, 4, "PROGRESS_APPLET_UPGRADE");

        if(do_force_format)  {
            bool skip_auth = true;
            if(Format(session,extensions,skip_auth) != STATUS_NO_ERROR )  {
                    PR_snprintf(audit_msg,512, "ForceUpgradeApplet error");
                    status = STATUS_ERROR_MAC_ENROLL_PDU; 
                    goto loser;
                } else {
                    RA::Debug(LL_PER_CONNECTION, "RA_Enroll_Processor::Process",
                              "after Successful ForceUpdgradeApplet, succeeded!");

                    PR_snprintf(audit_msg,512, "ForceUpgradeApplet succeeded as per policy.");
                   status = STATUS_NO_ERROR;
                    goto loser;

                }
        }  else {
            if (! CheckAndUpgradeApplet(
		    session,
		    extensions,
		    cuid,
		    tokenType,
		    final_applet_version,
		    app_major_version, app_minor_version,
		    //appletVersion,
		    NetKeyAID,
               	    msn,
            	    userid,
		    status, 
       		    &keyVersion)) {
                PR_snprintf(audit_msg, 512, "CheckAndUpgradeApplet error");
		goto loser;
	      }
      }

      RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "enrollment",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "applet upgraded successfully");

    isPinPresent = IsPinPresent(session, 0x0);

	StatusUpdate(session, extensions, 12, "PROGRESS_KEY_UPGRADE");

	if (!CheckAndUpgradeSymKeys(
		session,
		extensions,
		cuid,
		tokenType,
		msn,
                final_applet_version,
                userid,
                keyVersion,
		CardManagerAID,
		NetKeyAID,
		channel,
		status)) 
	{
                PR_snprintf(audit_msg, 512, "CheckAndUpgradeSymKeys error");
		goto loser;
	}
		
    /* we should have a good channel here */
    if (channel == NULL) {
            RA::Error(FN, "no good channel");
            status = STATUS_ERROR_CREATE_CARDMGR;
            PR_snprintf(audit_msg, 512, "secure channel setup error");
            goto loser;
    }

    if (channel != NULL) {
	if( keyVersion != NULL ) {
		PR_Free( (char *) keyVersion );
		keyVersion = NULL;
	}
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }
    
	StatusUpdate(session, extensions, 14, "PROGRESS_TOKEN_AUTHENTICATION");

    rc = channel->ExternalAuthenticate();
    if (rc == -1) {
      RA::Error(FN, "external authenticate failed");
        status = STATUS_ERROR_CREATE_CARDMGR;
        PR_snprintf(audit_msg, 512, "external authentication error");
        goto loser;
    }

    RA::Debug(LL_PER_CONNECTION, FN, "after SetupSecureChannel, succeeded");

    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {

      PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.minLen", OP_PREFIX, tokenType);
      unsigned int minlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 4);
      PR_snprintf((char *)configname, 256,"%s.%s.pinReset.pin.maxLen", OP_PREFIX, tokenType);
      unsigned int maxlen = RA::GetConfigStore()->GetConfigAsUnsignedInt(configname, 10);
     
      new_pin = RequestNewPin(session, minlen, maxlen);
      if (new_pin == NULL) {
	RA::Error(FN, "new pin request failed");

        status = STATUS_ERROR_MAC_RESET_PIN_PDU;
        PR_snprintf(audit_msg, 512, "new pin request error");
        goto loser;
      }
      RA::Debug(LL_PER_CONNECTION, "RA_Enroll_Processor::Process",
	      "after RequestNewPin, succeeded");

    RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "enrollment",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "RequestNewPin completed successfully");

    PR_snprintf((char *)configname, 256, "%s.%s.pinReset.enable", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
      if (!isPinPresent) {
    	PR_snprintf((char *)configname, 256, "%s.%s.pinReset.pin.maxRetries", OP_PREFIX, tokenType);
	maxRetries = RA::GetConfigStore()->GetConfigAsInt(configname, 0x7f);
        RA::Debug(LL_PER_CONNECTION, FN,
	      "param=%s maxRetries=%d", configname, maxRetries);
        rc = channel->CreatePin(0x0, 
		maxRetries,
		RA::GetConfigStore()->GetConfigAsString("create_pin.string", "password"));
        if (rc == -1) {
	    RA::Error("RA_Enroll_Processor::Process",
		  "create pin failed");

            status = STATUS_ERROR_MAC_RESET_PIN_PDU;
            PR_snprintf(audit_msg, 512, "create pin request error");
            goto loser;
        }


        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
           userid != NULL ? userid : "",
           cuid != NULL ? cuid : "",
           msn != NULL ? msn : "",
           "success",
           "enrollment",
           final_applet_version != NULL ? final_applet_version : "",
           keyVersion != NULL ? keyVersion : "",
           "CreatePin completed successfully");

      }
    }

      rc = channel->ResetPin(0x0, new_pin);
      if (rc == -1) {
	  RA::Error("RA_Enroll_Processor::Process",
		  "reset pin failed");

          status = STATUS_ERROR_MAC_RESET_PIN_PDU;
          PR_snprintf(audit_msg, 512, "reset pin request error");
          goto loser;
      }

      RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
        userid != NULL ? userid : "",
        cuid != NULL ? cuid : "",
        msn != NULL ? msn : "",
        "success",
        "enrollment",
        final_applet_version != NULL ? final_applet_version : "",
        keyVersion != NULL ? keyVersion : "",
        "ResetPin completed successfully");
    }

    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	      "after ResetPin, succeeded");

    // to help testing, we may use fix challenge
    PR_snprintf((char *)configname, 256, "%s.%s.generateChallenge", OP_PREFIX, tokenType);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 1)) {
      /* generate challenge for enrollment */
      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	      "Generate Challenge");
/*
 random number generation moved to TKS
      rc = Util::GetRandomChallenge(*plaintext_challenge);
      if (rc == -1) {
	RA::Error("RA_Enroll_Processor::Process",
		  "random challenge creation failed");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "general challenge error", "", tokenType);
        goto loser;
      }
*/

    }
    kdd =  channel->GetKeyDiversificationData();
    khex = kdd.toHex();
    RA::Debug("RA_Enroll_Processor::Process", "cuid=%s", khex);

    PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
    connid = RA::GetConfigStore()->GetConfigAsString(configname);
    /* wrap challenge with KEK key */
    rc = EncryptData(kdd,
      channel->GetKeyInfoData(), *plaintext_challenge, *wrapped_challenge, connid);
    if (rc == -1) {
	RA::Error("RA_Enroll_Processor::Process",
		  "encryt data failed");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        PR_snprintf(audit_msg, 512, "challenge encryption error");
        goto loser;
    }
    // read objects back
    PR_snprintf((char *)configname, 256, "%s.%s.pkcs11obj.enable", 
		    OP_PREFIX, tokenType);
    pkcs11obj_enable = RA::GetConfigStore()->GetConfigAsBool(configname, 1);

    if (pkcs11obj_enable) {
      pkcs11objx = new PKCS11Obj();

      // read old objects
      seq = 0x00;
      lastFormatVersion = 0x0100;
      //      lastObjectVersion = 0;
      if (getRandomNumber(&lastObjectVersion) != SECSuccess) {
          RA::Error(LL_PER_PDU, "RA_Enroll_Processor::Process",
	    "Could not generate a random version number...assigning 0x00");
          lastObjectVersion = 0x00;
      } else {
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
            "got random version numer: %ul", lastObjectVersion);
      }

      foundLastObjectVersion = 0;
      do {
        object = ListObjects(session, seq);
	if (object == NULL) {
		seq = 0;
	} else {
		seq = 1; // get next entry
		Buffer objectID = object->substr(0, 4);
		Buffer objectLen = object->substr(4, 4);
		unsigned long objectIDVal = 
			((((BYTE *)objectID)[0] << 24)) + 
			((((BYTE *)objectID)[1] << 16)) + 
			((((BYTE *)objectID)[2] << 8)) + 
			((((BYTE *)objectID)[3]));
		unsigned long objectLenVal = 
			((((BYTE *)objectLen)[0] << 24)) + 
			((((BYTE *)objectLen)[1] << 16)) + 
			((((BYTE *)objectLen)[2] << 8)) + 
			((((BYTE *)objectLen)[3]));

		Buffer *o = channel->ReadObject((BYTE*)objectID, 0, 
				(int)objectLenVal);
        if (o == NULL) {
          status = STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY;
          PR_snprintf(audit_msg, 512, "error in creating token entry");
          goto loser;
        }
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
                     "object read from token");

		if (((unsigned char *)objectID)[0] == 'z' && 
				((unsigned char *)objectID)[1] == '0') {
			lastFormatVersion = (((BYTE*)*o)[0] << 8) + 
					(((BYTE*)*o)[1]);
			lastObjectVersion = (((BYTE*)*o)[2] << 8) + 
					(((BYTE*)*o)[3]);
      			foundLastObjectVersion = 1;

			//
			delete pkcs11objx;
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
                     "parsing pkcs11obj read from token");
			pkcs11objx = PKCS11Obj::Parse(o, 0);
			seq = 0;
		} else {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
                     "new pkcs11obj");
			ObjectSpec *objSpec = 
				ObjectSpec::ParseFromTokenData(objectIDVal, o);
			if (objSpec != NULL) {
				pkcs11objx->AddObjectSpec(objSpec);
			}
		}

		delete o; 
		delete object;
	}
      } while (seq != 0);

    }

    rc = RA::tdb_add_token_entry((char *)userid, cuid, "uninitialized", tokenType);
    if (rc == -1) {
        status = STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY;
        PR_snprintf(audit_msg, 512, "error in creating uninitialized token entry");
        goto loser;
    }

	StatusUpdate(session, extensions, 15, "PROGRESS_PROCESS_PROFILE");

    tokentype = (char *)malloc(256 * sizeof(char)) ;
    PL_strcpy(tokentype, tokenType);
    /* generate signing key on netkey */
    if (!GenerateCertsAfterRecoveryPolicy(login, session, origins, ktypes, tokentype, pkcs11objx, 
      pkcs11obj_enable, extensions, channel, wrapped_challenge, 
      key_check, plaintext_challenge, cuid, msn, final_applet_version, 
      khex, userid, status, certificates, o_certNums, tokenTypes)) {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process"," - GenerateCertsAfterRecoveryPolicy returns false");
        goto loser;
    } else {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process"," - GenerateCertsAfterRecoveryPolicy returns true");
        if (status == STATUS_NO_ERROR) {
            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process"," - after GenerateCertsAfterRecoveryPolicy", "status is STATUS_NO_ERROR");
            if (!GenerateCertificates(login, session, origins, ktypes, tokentype, pkcs11objx, 
              pkcs11obj_enable, extensions, channel, wrapped_challenge, 
              key_check, plaintext_challenge, cuid, msn, final_applet_version, 
              khex, userid, status, certificates, o_certNums, tokenTypes)) {
                RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertificates"," returns false might as well clean up token.");
                bool skip_auth = true;
                Format(session,extensions,skip_auth);
                goto loser;
            } else {
                RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertificates"," returns true");
            }
        } else {
            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertsAfterRecoveryPolicy", "status is %d", status);
        }
    }

    if ((status == STATUS_ERROR_RENEWAL_IS_PROCESSED) &&
            RA::ra_allow_token_renew(cuid)) {
        renewed = true;
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "renewal happened.. "); 
    }
    
    // read objects back
    if (pkcs11obj_enable) {
      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "pkcs11obj enabled"); 
      pkcs11objx->SetFormatVersion(lastFormatVersion);
      if (foundLastObjectVersion) {
          while (lastObjectVersion == 0xff) {
              if (getRandomNumber(&lastObjectVersion) != SECSuccess) {
                  RA::Error(LL_PER_PDU, "RA_Enroll_Processor::Process",
                    "Encounter 0xff, could not generate a random version number...assigning 0x00");
                  lastObjectVersion = 0x00;
              } else {
                  RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
                    "Encounter 0xff, got random version numer: %ul", lastObjectVersion);
              }
           }

           pkcs11objx->SetObjectVersion(lastObjectVersion+1);
      } else {
      	pkcs11objx->SetObjectVersion(lastObjectVersion);
      }
      pkcs11objx->SetCUID(token_cuid);

      /* add additional certificate objects */
      PR_snprintf((char *)configname, 256, "%s.certificates.num", 
		    OP_PREFIX);
      int certNum = RA::GetConfigStore()->GetConfigAsInt(configname);
      if (certNum > 0) {
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "about to write certificate chain");
      }
      for (int i = 0; i < certNum; i++) {

        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "root certificate #%d", i);

        PR_snprintf((char *)configname, 256, "%s.certificates.value.%d", 
		    OP_PREFIX, i);
        char *certName = (char *)RA::GetConfigStore()->GetConfigAsString(configname);

        /* retrieve certificate info */
        PR_snprintf((char *)configname, 256, "%s.certificates.%s.nickName", 
		    OP_PREFIX, certName);
        char *certNickName = (char *)RA::GetConfigStore()->GetConfigAsString(configname);
        PR_snprintf((char *)configname, 256, "%s.certificates.%s.certId", 
		    OP_PREFIX, certName);
        char *certId = (char *)
          RA::GetConfigStore()->GetConfigAsString(configname, "C0");

/*
op.enroll.certificates.num=1
op.enroll.certificates.value.0=caCert
op.enroll.certificates.caCert.nickName=caCert0 fpki-tps
op.enroll.certificates.caCert.certId=C5
op.enroll.certificates.caCert.certAttrId=c5
op.enroll.certificates.caCert.label=caCert Label
 */

        /* retrieve certificate */
        CERTCertificate *cert = CERT_FindCertByNickname(
                CERT_GetDefaultCertDB(), certNickName);

        if (cert == NULL) {
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Cannot find certificate %s", certNickName);
        } else {
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Found certificate %s", certNickName);

          /* add certificate to z object */
          Buffer *certBuf = new Buffer((BYTE*)cert->derCert.data, 
                        (unsigned int)cert->derCert.len);
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Certificate buffer created");
	      ObjectSpec *objSpec = ObjectSpec::ParseFromTokenData(
				(certId[0] << 24) +
				(certId[1] << 16), certBuf);
	      pkcs11objx->AddObjectSpec(objSpec);
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Certificate object Added to PKCS11 Object");

          /* add PK11 attributes */
        PR_snprintf((char *)configname, 256, "%s.certificates.%s.label", 
		    OP_PREFIX, certName);
        char *certLabel = (char *)RA::GetConfigStore()->GetConfigAsString(configname);
        PR_snprintf((char *)configname, 256, "%s.certificates.%s.certAttrId", 
		    OP_PREFIX, certName);
        char *certAttrId = (char *)
          RA::GetConfigStore()->GetConfigAsString(configname, "c0");

          Buffer *keyid = NULL;
          if (cert->subjectKeyID.data != NULL) {
            keyid = new Buffer((BYTE*)cert->subjectKeyID.data,
                                    (unsigned int)cert->subjectKeyID.len);
          } else {
            SECItem *pubKeyData = PK11_GetPubIndexKeyID(cert) ;
            SECItem *tmpitem = PK11_MakeIDFromPubKey(pubKeyData);
            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Got Key ID");
         
             
            keyid = new Buffer((BYTE*)tmpitem->data, 
                                         (unsigned int)tmpitem->len);
          }

          Buffer b = channel->CreatePKCS11CertAttrsBuffer(
                   KEY_TYPE_ENCRYPTION /* not being used */, 
                   certAttrId, certLabel, keyid);
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Created buffer for PKCS11 cert attributes");
	      objSpec = ObjectSpec::ParseFromTokenData(
							   (certAttrId[0] << 24) +
							   (certAttrId[1] << 16),
							   &b);
	      pkcs11objx->AddObjectSpec(objSpec);
          RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "Added PKCS11 certificate attribute");
        }
      }
      
      // build label
      PR_snprintf((char *)configname, 256, "%s.%s.keyGen.tokenName", 
		    OP_PREFIX, tokentype);
      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "tokenName '%s'",
		   configname);
      pattern = RA::GetConfigStore()->GetConfigAsString(configname, "$cuid$");
      nv.Add("cuid", cuid);
      nv.Add("msn", msn);
      nv.Add("userid", userid);
      nv.Add("profileId", tokenType);

      /* populate auth parameters output to nv also */
      /* so we can reference to the auth parameter by */
      /* using $auth.cn$, or $auth.mail$ */
      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "Check login");
      if (login != NULL) {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "Found login");
        int s = login->Size();
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "login size=%d", s);
        for (int x = 0; x < s; x++) {
           char namebuf[2048];
           char *name = login->GetNameAt(x);
           sprintf(namebuf, "auth.%s", name);
           if (strcmp(name,"PASSWORD") != 0) {
             RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "Exposed %s=%s", namebuf, login->GetValue(name));
           }
           nv.Add(namebuf, login->GetValue(name));
        }
      }
      label = MapPattern(&nv, (char *) pattern);
      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "labelName '%s'",
		   label);
      labelBuffer = Buffer((BYTE*)label, strlen(label));
      pkcs11objx->SetTokenName(labelBuffer); 

      // write PKCS11 Obj
      BYTE objid[4];

      objid[0] = 'z';
      objid[1] = '0';
      objid[2] = 0;
      objid[3] = 0;
      Buffer xb;

      PR_snprintf((char *)configname, 256, "%s.%s.pkcs11obj.compress.enable", 
		    OP_PREFIX, tokentype);
      compress = RA::GetConfigStore()->GetConfigAsBool(configname, 1);

      if (compress) {
      	xb = pkcs11objx->GetCompressedData(); 
        RA::Debug("RA_Enroll_Processor::Process PKCSData", "Compressed Data");
      } else {
      	xb = pkcs11objx->GetData(); 
        RA::Debug("RA_Enroll_Processor::Process PKCSData", "Uncompressed Data");
      }
      RA::DebugBuffer("RA_Enroll_Processor::Process PKCSData", "PKCS Data=", &xb);


      if(xb.size() == 0)  {
          status = STATUS_ERROR_MAC_ENROLL_PDU;
          RA::Debug("RA_Enroll_Processor::Failure to get token object!"," failed");
          PR_snprintf(audit_msg, 512, "channel createObject failed");
          goto loser;
      }

      if((int) xb.size() > totalAvailableMemory) {
          status = STATUS_ERROR_MAC_ENROLL_PDU;
          RA::Debug("RA_Enroll_Processor::Failure pkcs11 object may exceed applet memory"," failed");
          PR_snprintf(audit_msg, 512, "Applet memory exceeded when writing out final token data");
          bool skip_auth = true;
          if(!renewed) { //Renewal should leave what they have on the token.
          	Format(session,extensions,skip_auth);
          }
          goto loser;
      }

	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

	if (channel->CreateObject(objid, perms, xb.size()) != 1) {
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
          RA::Debug("RA_Enroll_Processor::channel createObject"," failed");
          PR_snprintf(audit_msg, 512, "channel createObject failed");
	  goto loser;
	}
      //      channel->CreateObject(objid, xb.size());
	if (channel->WriteObject(objid, (BYTE*)xb, xb.size()) != 1) {
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
          RA::Debug("RA_Enroll_Processor::channel writeObject"," failed");
          PR_snprintf(audit_msg, 512, "channel writeObject failed");
	  goto loser;
	}
    }

	StatusUpdate(session, extensions, 90, "PROGRESS_SET_LIFE_CYCLE_STATE");
    
    // add issuer info to the token
    PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.enable",
          OP_PREFIX, tokenType);
    RA::Debug("RA_Enroll_Processor", "Getting %s", configname);
    if (RA::GetConfigStore()->GetConfigAsBool(configname, 0)) {
        if (channel != NULL) {
            char issuer[224];
            for (int i = 0; i < 224; i++) {
              issuer[i] = 0;
            }
            PR_snprintf((char *)configname, 256, "%s.%s.issuerinfo.value",
               OP_PREFIX, tokenType);
            char *issuer_val = (char*)RA::GetConfigStore()->GetConfigAsString(
                                   configname);
            RA::Debug("RA_Enroll_Processor", 
              "Before pattern substitution mapping is %s", issuer_val);
            issuer_val = MapPattern(&nv, (char *) issuer_val);
            RA::Debug("RA_Enroll_Processor", 
              "After pattern substitution mapping is %s", issuer_val);
            sprintf(issuer, "%s", issuer_val);
            RA::Debug("RA_Enroll_Processor", "Set Issuer Info %s", issuer_val);
            Buffer *info = new Buffer((BYTE*)issuer, 224);
            rc = channel->SetIssuerInfo(info);
      
            if (info != NULL) {
                delete info;
                info = NULL;
            }
        }
    }
    /* write lifecycle bit */
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "Set Lifecycle State");
    rc = channel->SetLifecycleState(0x0f);
    if (rc == -1) {
        RA::Error("RA_Enroll_Processor::Process",
		"Set life cycle state failed");
        status = STATUS_ERROR_MAC_LIFESTYLE_PDU;
        PR_snprintf(audit_msg, 512, "set life cycle state error");
        goto loser;
    }

    rc = channel->Close();
    if (rc == -1) {
        RA::Error("RA_Enroll_Processor::Process",
		"Failed to close channel");
        status = STATUS_ERROR_CONNECTION;
        PR_snprintf(audit_msg, 512, "channel not closed");
        goto loser;
    }
    
	StatusUpdate(session, extensions, 100, "PROGRESS_DONE");

    status = STATUS_NO_ERROR;

    sprintf(activity_msg, "applet_version=%s tokenType=%s userid=%s", 
           final_applet_version, tokentype, userid);

    if (renewed) {
        RA::tdb_activity(session->GetRemoteIP(), cuid, "renewal", "success", activity_msg, userid, tokenType);
    } else {
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "success", activity_msg, userid, tokenType);
    }
    RA::tdb_update((char *)userid, cuid, (char *)final_applet_version, (char *)keyVersion, "active", "", tokenType);
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after tdb_update()");

    RA::tdb_update_certificates(cuid, tokenTypes, (char*)userid, certificates, ktypes, origins, o_certNums);
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after tdb_update_certificates()");

    rc = 1;

    end = PR_IntervalNow();
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after end");

    /* audit log for successful enrollment */
    if (renewed) { 
        if (authid != NULL) { 
            PR_snprintf(activity_msg, 4096, "renewal processing completed, authid = %s", authid);
        } else {
            PR_snprintf(activity_msg, 4096, "renewal processing completed");
        }
        RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC,
          userid, cuid, msn, "success", "renewal", final_applet_version, keyVersion, activity_msg);
    } else { 
        if (authid != NULL) { 
            PR_snprintf(activity_msg, 4096, "enrollment processing completed, authid = %s", authid);
        } else {
            PR_snprintf(activity_msg, 4096, "enrollment processing completed");
        }
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid, cuid, msn, "success", "enrollment", final_applet_version, keyVersion, activity_msg);
    }

    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after audit, o_certNums=%d",o_certNums);

loser:

    if (strlen(audit_msg) > 0) { // a failure occurred
        if (renewed) { 
            RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC,
              userid != NULL ? userid : "", 
              cuid != NULL ? cuid : "", 
              msn != NULL ? msn : "", 
              "failure", 
              "renewal", 
              final_applet_version != NULL ? final_applet_version : "", 
              keyVersion != NULL ? keyVersion : "", 
              audit_msg);

            if ((cuid != NULL) && (tokenType != NULL)) {
                RA::tdb_activity(session->GetRemoteIP(),
                    cuid, 
                    "renewal", 
                    "failure",
                    audit_msg, 
                    userid != NULL? userid : "", 
                    tokenType);
            }
        } else { 
            RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
              userid != NULL ? userid : "", 
              cuid != NULL ? cuid : "", 
              msn != NULL ? msn : "", 
              "failure", 
              "enrollment", 
              final_applet_version != NULL ? final_applet_version : "", 
              keyVersion != NULL ? keyVersion : "", 
              audit_msg);

            if ((cuid != NULL) && (tokenType != NULL)) {
                RA::tdb_activity(session->GetRemoteIP(),
                    cuid, 
                    "enrollment", 
                    "failure",
                    audit_msg, 
                    userid != NULL? userid : "", 
                    tokenType);
            }
        }
    }

    if (tokenTypes != NULL) {
        for (int nn=0; nn<o_certNums; nn++) {
            if (tokenTypes[nn] != NULL)
                PL_strfree(tokenTypes[nn]);
            tokenTypes[nn] = NULL;
        }
        free(tokenTypes);
        tokenTypes = NULL;
    }
    if (certificates != NULL) {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "before CERT_DestroyCertificate.  certNums=%d", o_certNums);
        for (int i=0;i < o_certNums; i++) {
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "CERT_DestroyCertificate:  i=%d", i);
            if (certificates[i] != NULL) {
                   CERT_DestroyCertificate(certificates[i]);
            }
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "CERT_DestroyCertificate:  i=%i done", i);
        }
        free(certificates);
        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after CERT_DestroyCertificate");
    }

    if( certEnroll != NULL ) {
        delete certEnroll;
        certEnroll = NULL;
    }

    if (ktypes != NULL) {
       for (int nn=0; nn < o_certNums; nn++) {
           if (ktypes[nn] != NULL)
               PL_strfree(ktypes[nn]);
           ktypes[nn] = NULL;
       } 
       free(ktypes);
       ktypes = NULL;
    }

    if (origins != NULL) {
       for (int nn=0; nn < o_certNums; nn++) {
           if (origins[nn] != NULL)
               PL_strfree(origins[nn]);
           origins[nn] = NULL;
       }
       free(origins);
       origins = NULL;
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

    if( channel != NULL ) {
        delete channel;
        channel = NULL;
    }

    if( new_pin != NULL ) {
        PL_strfree( new_pin );
        new_pin = NULL;
    }

    if( key_check != NULL ) {
        delete key_check;
        key_check = NULL;
    }

    if( wrapped_challenge != NULL ) {
        delete wrapped_challenge;
        wrapped_challenge = NULL;
    }

    if( plaintext_challenge != NULL ) {
        delete plaintext_challenge;
        plaintext_challenge = NULL;
    }

    if( token_status != NULL ) {
        delete token_status;
        token_status = NULL;
    }
    
    if( final_applet_version != NULL ) {
        PR_Free( (char *) final_applet_version );
        final_applet_version = NULL;
    }
 
    if( appletVersion != NULL ) {
        PR_Free( (char *) appletVersion );
        appletVersion = NULL;
    }
    if( khex != NULL ) {
        PR_Free( khex );
        khex = NULL;
    }
    if( keyVersion != NULL ) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }
    if( userid != NULL ) {
        PR_Free( (char *) userid );
        userid = NULL;
    }
    if (token_state != NULL) {
        PR_Free((char *)token_state);
        token_state = NULL;
    }
    if( cuid != NULL ) {
        PR_Free( cuid );
        cuid = NULL;
    }
    if( msn != NULL ) {
        PR_Free( msn );
        msn = NULL;
    }
    if( label != NULL ) {
        PL_strfree( (char *) label );
        label = NULL;
    }
    if (tokentype != NULL) {
      PR_Free(tokentype);
    }
    if (pkcs11objx != NULL) {
      delete pkcs11objx;
    }

#ifdef   MEM_PROFILING     
            MEM_dump_unfree();
#endif

    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "returning status");
    return status;
}


bool RA_Enroll_Processor::GenerateCertificates(AuthParams *login, RA_Session *session, char **&origins, char **&ktypes, 
  char *tokenType, PKCS11Obj *pkcs11objx, int pkcs11obj_enable, 
  NameValueSet *extensions, Secure_Channel *channel, Buffer *wrapped_challenge,
  Buffer *key_check, Buffer *plaintext_challenge, char *cuid, char *msn,
  const char *final_applet_version, char *khex, const char *userid, RA_Status &o_status, 
  CERTCertificate **&certificates, int &o_certNums, char **&tokenTypes) {

    bool noFailedCerts = true;
    bool r=true;
    int keyTypeNum = 0;
    int i = 0;
    char configname[256];
	const char *FN = "RA_Enroll_Processor::GenerateCertificates";
    RA_Status lastErrorStatus = STATUS_NO_ERROR;


    RA::Debug(LL_PER_CONNECTION,FN, "tokenType=%s", tokenType); 
    PR_snprintf((char *)configname, 256, "%s.%s.keyGen.keyType.num", OP_PREFIX, tokenType);
    keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname);
    if (keyTypeNum == 0) {
        r = false;
        RA::Error(LL_PER_CONNECTION,FN,
                        "Profile parameters are not found");
        o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        goto loser; 
    }

    ktypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    origins = (char **) malloc (sizeof(char *) * keyTypeNum);
    tokenTypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * keyTypeNum);
    o_certNums = keyTypeNum;
    for (i=0; i<keyTypeNum; i++) {
		certificates[i] = NULL;
		ktypes[i] = NULL;
		origins[i] = NULL;
		tokenTypes[i] = NULL;

    }
    for (i=0; i<keyTypeNum; i++) {

        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.keyType.value.%d", OP_PREFIX, tokenType, i);
        const char *keyTypeValue = RA::GetConfigStore()->GetConfigAsString(configname, "signing");

        r = GenerateCertificate(login,keyTypeNum, keyTypeValue, i, session, origins, ktypes, tokenType,
          pkcs11objx, pkcs11obj_enable, extensions, channel, wrapped_challenge,
          key_check, plaintext_challenge, cuid, msn, final_applet_version,
          khex, userid, o_status, certificates);

        RA::Debug("GenerateCertificates","configname %s  result  %d",configname,r);

        tokenTypes[i] = PL_strdup(tokenType);
        if(r == false)  {
            noFailedCerts  = false;
            lastErrorStatus = o_status;
            break;
       }
            
    }

    if (noFailedCerts == true) {
    //In this special case of re-enroll
    //Revoke  current certs for this token  
    // before the just enrolled certs are written to the db
         char error_msg[512];
         bool success = RevokeCertificates(session, cuid,error_msg,(char *)final_applet_version,
                                             NULL,(char *)tokenType,(char *)userid,o_status
         );

         RA::Debug("GenerateCertificates","Revoke result %d  ",(int) success);

         if (!success) {
              //Don't blow the whole thing up for this.
              RA::Debug("GenerateCertificates","Revocation failure %s  ",error_msg);
         }

    }
 loser:
    if(lastErrorStatus != STATUS_NO_ERROR) {
        o_status = lastErrorStatus;
    }
    return noFailedCerts;
}

bool RA_Enroll_Processor::GenerateCertificate(AuthParams *login, int keyTypeNum, const char *keyTypeValue, int i, RA_Session *session, 
  char **origins, char **ktypes, char *tokenType, PKCS11Obj *pkcs11objx, int pkcs11obj_enable,
  NameValueSet *extensions, Secure_Channel *channel, Buffer *wrapped_challenge,
  Buffer *key_check, Buffer *plaintext_challenge, char *cuid, char *msn,
  const char *final_applet_version, char *khex, const char *userid, 
  RA_Status &o_status, CERTCertificate **certificates)
{
    bool r = true;
    char configname[256];
    char keyTypePrefix[200];
	const char *FN="RA_Enroll_Processor::GenerateCertificate";

    PR_snprintf((char *)keyTypePrefix, 256, "%s.%s.keyGen.%s", OP_PREFIX, tokenType, keyTypeValue);
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::GenerateCertificate","keyTypePrefix is %s",keyTypePrefix);
    PR_snprintf((char *)configname, 256, "%s.ca.profileId", keyTypePrefix);
    const char *profileId = RA::GetConfigStore()->GetConfigAsString(configname, "");
    PR_snprintf((char *)configname, 256,"%s.certId", keyTypePrefix);
    const char *certId = RA::GetConfigStore()->GetConfigAsString(configname, "C0");
    PR_snprintf((char *)configname, 256, "%s.certAttrId", keyTypePrefix);
    const char *certAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "c0");
    PR_snprintf((char *)configname, 256, "%s.privateKeyAttrId", keyTypePrefix);
    const char *priKeyAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "k0"); 
    PR_snprintf((char *)configname,  256,"%s.publicKeyAttrId", keyTypePrefix);
    const char *pubKeyAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "k1");
    PR_snprintf((char *)configname, 256, "%s.keySize", keyTypePrefix);
    int keySize = RA::GetConfigStore()->GetConfigAsInt(configname, 1024);


    PR_snprintf((char *)configname, 256, "%s.alg", keyTypePrefix);
    //Default RSA_CRT=2
    BYTE algorithm = (BYTE) RA::GetConfigStore()->GetConfigAsInt(configname, 2);

    PR_snprintf((char *)configname, 256, "%s.publisherId", keyTypePrefix);
    const char *publisherId = RA::GetConfigStore()->GetConfigAsString(configname, NULL);

    PR_snprintf((char *)configname, 256, "%s.keyUsage", keyTypePrefix);
    int keyUsage = RA::GetConfigStore()->GetConfigAsInt(configname, 0);
    PR_snprintf((char *)configname, 256, "%s.keyUser", keyTypePrefix);
    int keyUser = RA::GetConfigStore()->GetConfigAsInt(configname, 0);
    PR_snprintf((char *)configname, 256, "%s.privateKeyNumber", keyTypePrefix);
    int priKeyNumber = RA::GetConfigStore()->GetConfigAsInt(configname, 0);
    PR_snprintf((char *)configname, 256, "%s.publicKeyNumber", keyTypePrefix);
    int pubKeyNumber = RA::GetConfigStore()->GetConfigAsInt(configname, 1);


    // get key capabilites to determine if the key type is SIGNING, 
    // ENCRYPTION, or SIGNING_AND_ENCRYPTION
    PR_snprintf((char *)configname, 256, "%s.private.keyCapabilities.sign", keyTypePrefix);
    bool isSigning = RA::GetConfigStore()->GetConfigAsBool(configname);
    PR_snprintf((char *)configname, 256, "%s.public.keyCapabilities.encrypt", keyTypePrefix);
    bool isEncrypt = RA::GetConfigStore()->GetConfigAsBool(configname);
    int keyTypeEnum = 0;

    if ((isSigning) &&
        (isEncrypt)) {
        keyTypeEnum = KEY_TYPE_SIGNING_AND_ENCRYPTION;
    } else if (isSigning) {
        keyTypeEnum = KEY_TYPE_SIGNING;
    } else if (isEncrypt) {
        keyTypeEnum = KEY_TYPE_ENCRYPTION;
    }
    RA::Debug(LL_PER_CONNECTION,FN,
		"key type is %d",keyTypeEnum);

    PR_snprintf((char *)configname, 256, "%s.ca.conn", keyTypePrefix);
    const char *caconnid = RA::GetConfigStore()->GetConfigAsString(configname);
    certificates[i] = NULL;
    ktypes[i] = NULL;
    origins[i] = NULL;

    o_status = DoEnrollment(login, session, certificates, origins, ktypes, pkcs11obj_enable,
                    pkcs11objx, extensions, i, keyTypeNum,
                    15 /* start progress */,
                    90 /* end progress */, channel, wrapped_challenge,
          tokenType,
          keyTypeValue,
          key_check,
          plaintext_challenge,
          cuid,
          msn,
          khex, (TokenKeyType)keyTypeEnum, profileId, userid, certId,publisherId, certAttrId, priKeyAttrId,
          pubKeyAttrId, (keyUser << 4)+priKeyNumber,
          (keyUsage << 4)+pubKeyNumber, algorithm, keySize, caconnid, keyTypePrefix,(char *)final_applet_version);

    if (o_status != STATUS_NO_ERROR) {
        r = false;

        RA::Debug(LL_PER_CONNECTION,FN,
			"Got a status error from DoEnrollment:  %d", o_status);
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "enrollment error", "", tokenType);
        goto loser;
    }

 loser:

    return r;
}
  
bool RA_Enroll_Processor::GenerateCertsAfterRecoveryPolicy(AuthParams *login, RA_Session *session, char **&origins, char **&ktypes, 
  char *&tokenType, PKCS11Obj *pkcs11objx, int pkcs11obj_enable, 
  NameValueSet *extensions, Secure_Channel *channel, Buffer *wrapped_challenge,
  Buffer *key_check, Buffer *plaintext_challenge, char *cuid, char *msn,
  const char *final_applet_version, char *khex, const char *userid, RA_Status &o_status, 
  CERTCertificate **&certificates, int &o_certNums, char **&tokenTypes)
{
    LDAPMessage *ldapResult = NULL;
    LDAPMessage *e = NULL;
    int nEntries = 0;
    char filter[512];
    char configname[512];
    char tokenStatus[100];
    char *tokenid = NULL;
    int rc = -1;
    bool r=true;
    o_status = STATUS_NO_ERROR;
    char *origTokenType = NULL;

	const char *FN="RA_Enroll_Process::GenerateCertsAfterRecoveryPolicy";
    PR_snprintf(filter, 512, "tokenUserID=%s", userid);
    
    rc = RA::ra_find_tus_token_entries_no_vlv(filter, &ldapResult, 1);
  
    if (rc != LDAP_SUCCESS) {
        RA::Debug(LL_PER_CONNECTION,FN,
			"Cant find any tokens associated with the userid=%s. "
			"There should be at least one token.", userid);
        r = false;
        o_status = STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND;
        goto loser;
    } else {
        nEntries = RA::ra_get_number_of_entries(ldapResult);
        for (e = RA::ra_get_first_entry(ldapResult); e != NULL; e = RA::ra_get_next_entry(e)) {   
            struct berval ** attr_values = RA::ra_get_attribute_values(e, "tokenStatus");

            if ((attr_values == NULL) || (attr_values[0] == NULL)) {
                RA::Debug(LL_PER_CONNECTION,FN, "Error obtaining token status");
                r = false;
                o_status = STATUS_ERROR_BAD_STATUS;
                if (attr_values != NULL) {
                    RA::ra_free_values(attr_values);
                    attr_values = NULL;
                }
                goto loser;
            }
          
            RA::Debug(LL_PER_CONNECTION,FN, "tokenStatus = %s",
              attr_values[0]->bv_val);

            strncpy(tokenStatus, attr_values[0]->bv_val, 100);
            // free attr_values
            if (attr_values != NULL) {
              RA::ra_free_values(attr_values);
              attr_values = NULL;
            }
            tokenid = RA::ra_get_token_id(e);
            RA::Debug(LL_PER_CONNECTION,FN, "tokenID = %s", tokenid);
            int cmp_result = PL_strcasecmp(tokenid, cuid);
            free(tokenid);
            if (cmp_result == 0) {
                if (PL_strcasecmp(tokenStatus, "uninitialized") == 0 ) {
                    if (nEntries == 1) {
                        // need to do enrollment outside
                        break;
                    } else {
                        RA::Debug(LL_PER_CONNECTION,FN,
                          "There are multiple token entries for user %s.", userid);

                        if (RA::ra_tus_has_active_tokens((char *)userid) == 0) {
                            r = false;
                            o_status = STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN;
                            RA::Debug(LL_PER_CONNECTION,FN, "User already has one active token.");
                            goto loser;
                        } else {
                            // 1) current token is in active state
                            // 2) there are no other active tokens for this user
                            // 3) that means the previous one is the lost one
                            // get the most recent previous token:
                            LDAPMessage *prev = RA::ra_get_next_entry(e);
                            char *reason = RA::ra_get_token_reason(prev);
                            char *lostTokenCUID = RA::ra_get_token_id(prev);

                            // if the previous one is lost, then check lost reason
                            origTokenType = PL_strdup(tokenType);
                            if (PL_strcasecmp(reason, "keyCompromise") == 0) {
                                r = ProcessRecovery(login, reason, session, origins, ktypes,
                                  tokenType, pkcs11objx, pkcs11obj_enable,
                                  extensions, channel, wrapped_challenge,
                                  key_check, plaintext_challenge, cuid, msn,
                                  final_applet_version, khex, userid,
                                  o_status, certificates, lostTokenCUID, o_certNums, tokenTypes, origTokenType); 

                                break;
                            } else if (PL_strcasecmp(reason, "onHold") == 0) {
                                // then the inactive one becomes the temp token
                                // No recovery scheme, basically we are going to
                                // do the brand new enrollment
                                PR_snprintf(configname, 512, "op.enroll.%s.temporaryToken.tokenType", tokenType);
                                char *tempTokenType = (char *)(RA::GetConfigStore()->GetConfigAsString(configname, "userKeyTemporary"));
                                RA::Debug(LL_PER_CONNECTION,FN, 
									"Token type for temporary token: %s", tempTokenType);
                                PL_strcpy(tokenType, tempTokenType);
                                r = ProcessRecovery(login, reason, session, origins, ktypes,
                                  tokenType, pkcs11objx, pkcs11obj_enable,
                                  extensions, channel, wrapped_challenge,
                                  key_check, plaintext_challenge, cuid, msn,
                                  final_applet_version, khex, userid,
                                  o_status, certificates, lostTokenCUID, o_certNums, tokenTypes, origTokenType); 

                                break;
                            } else if (PL_strcasecmp(reason, "destroyed") == 0) {
                                r = ProcessRecovery(login, reason, session, origins, ktypes,
                                  tokenType, pkcs11objx, pkcs11obj_enable,
                                  extensions, channel, wrapped_challenge,
                                  key_check, plaintext_challenge, cuid, msn,
                                  final_applet_version, khex, userid,
                                  o_status, certificates, lostTokenCUID, o_certNums, tokenTypes, origTokenType); 

                                break;
                            } else {
                                r = false;
                                o_status = STATUS_ERROR_NO_SUCH_LOST_REASON;
                                RA::Debug(LL_PER_CONNECTION,FN,
                                  "No such lost reason=%s for this cuid=%s",
                                  reason, cuid);
                                goto loser;
                            }
                        }
                    }
                } else if (strcmp(tokenStatus, "active") == 0) {
                    r = true;
                    RA::Debug(LL_PER_CONNECTION,FN,
			"This is the active token. You can re-enroll if the re-enroll=true; or renew if renew=true.");
                    if (RA::ra_allow_token_renew(cuid)) {
                        // renewal allowed instead of re-enroll
                        r = ProcessRenewal(login, session, ktypes, origins,
                                  tokenType, pkcs11objx, pkcs11obj_enable,
                                  channel,
                                  cuid, msn,
                                  final_applet_version, userid,
                                  o_status, certificates, o_certNums,
                                  tokenTypes); 
                        if (r == true) {
                            RA::Debug(LL_PER_CONNECTION,FN, "ProcessRenewal returns true");
                        } else
                            goto loser;
                    }
                    break;
                } else if (strcmp(tokenStatus, "terminated") == 0) {
                    RA::Debug(LL_PER_CONNECTION,FN,
                      "terminated token cuid=%s", cuid);
                    r = false;
                    o_status = STATUS_ERROR_CONTACT_ADMIN;
                    goto loser;
                } else if (strcmp(tokenStatus, "lost") == 0) {
                    char *reason = RA::ra_get_token_reason(e);
                    if (strcmp(reason, "keyCompromise") == 0) {
                        r = false;
                        o_status = STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE;
                        RA::Debug(LL_PER_CONNECTION,FN,
							"This token cannot be reused because it has been reported lost");
                        goto loser;
                    } else if (strcmp(reason, "onHold") == 0) {
                        if (RA::ra_tus_has_active_tokens((char *)userid) == 0) {
                            r = false;
                            o_status = STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN;
                            RA::Debug(LL_PER_CONNECTION,FN,
								"User already has an active token.");
                            goto loser;
                        } else { // change it back to active token
                            r = false;
                            o_status = STATUS_ERROR_CONTACT_ADMIN;
                            RA::Debug(LL_PER_CONNECTION,FN,
				"User needs to contact administrator to report lost token (it should be put on Hold).");
                            break;
                        }
                    } else if (strcmp(reason, "destroyed") == 0) {
                        r = false;
                        RA::Debug(LL_PER_CONNECTION,FN,
							"This destroyed lost case should not be executed because the token is so damaged. It should not get here");
                        o_status = STATUS_ERROR_TOKEN_DISABLED;
                        goto loser;
                    } else {
                        RA::Debug(LL_PER_CONNECTION,FN,
							"No such lost reason=%s for this cuid=%s", reason, cuid);
                        r = false;
                        o_status = STATUS_ERROR_NO_SUCH_LOST_REASON;
                        goto loser;
                    }
                } else {
                    RA::Debug(LL_PER_CONNECTION,FN,
                      "No such token status for this cuid=%s", cuid);
                    r = false;
                    o_status = STATUS_ERROR_NO_SUCH_TOKEN_STATE;
                    goto loser;
                }
            } else { // cuid != cuid of the current token
                continue;
/*
                if (RA::ra_tus_has_active_tokens((char *)userid) == 0) {
                    r = false;
                    o_status = STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN;
                    RA::Debug("RA_Enroll_Processor::GenerateCertsAfterRecoveryPolicy", "You already have one active token.");
                    goto loser;
                } else
                    continue;
*/
            }
        }
    }

 loser:
    if (origTokenType != NULL) {
        PL_strfree(origTokenType);
        origTokenType = NULL;
    }
    if (rc == 0)
        if (ldapResult != NULL)
            ldap_msgfree(ldapResult);


RA::Debug("RA_Enroll_Processor::GenerateCertsAfterRecoveryPolicy", "returning boolean = %d", r); 
    return r;
}

/*
 * cfu - check  if a cert is within the renewal grace period
 *  utilize passed in grace period values. 
 */
bool RA_Enroll_Processor::isCertRenewable(CERTCertificate *cert, int graceBefore, int graceAfter){
    PRTime timeBefore, timeAfter, now;

    //Grace period input in days
    RA::Debug("RA_Enroll_Processor::isCertRenewable","graceBefore %d graceAfter %d",graceBefore,graceAfter);
    PRTime graceBefore64, graceAfter64,microSecondsPerSecond;
    PRInt64 graceBeforeSeconds,graceAfterSeconds;

    LL_I2L(microSecondsPerSecond, PR_USEC_PER_SEC);

    //Get number of microseconds in each grace period value.
    LL_I2L(graceBeforeSeconds, graceBefore * 60 * 60 * 24);
    LL_I2L(graceAfterSeconds,graceAfter * 60 * 60 * 24);

    LL_MUL(graceBefore64, microSecondsPerSecond,graceBeforeSeconds);
    LL_MUL(graceAfter64,  microSecondsPerSecond,graceAfterSeconds);

    PRTime lowerBound, upperBound;
 
    DER_DecodeTimeChoice(&timeBefore, &cert->validity.notBefore);
    DER_DecodeTimeChoice(&timeAfter, &cert->validity.notAfter);

    PrintPRTime(timeBefore,"timeBefore");
    PrintPRTime(timeAfter,"timeAfter");

    now = PR_Now();

    //Calculate lower and upper legal bounds for time
    LL_SUB(lowerBound,timeAfter, graceBefore64);
    LL_ADD(upperBound,timeAfter,graceAfter64);

    PrintPRTime(lowerBound,"lowerBound");
    PrintPRTime(now,"now");
    PrintPRTime(upperBound,"upperBound");

    if(LL_CMP(now,>=, lowerBound) && LL_CMP(now,<=,upperBound)) {
        RA::Debug("RA_Enroll_Processor::isCertRenewable","returning true!");
        return true;
    }

    RA::Debug("RA_Enroll_Processor::isCertRenewable","returning false!");

    return false;
}

/*
 * cfu
 * DoRenewal - use i_cert's serial number for renewal
 * i_cert - cert to renew
 * o_cert - cert newly issued
 */
bool RA_Enroll_Processor::DoRenewal(const char *connid, const char *profileId, CERTCertificate *i_cert,
CERTCertificate **o_cert, char *error_msg, int *error_code)
{
    RA_Status status = STATUS_NO_ERROR;
    bool r = true;
    CertEnroll *certRenewal = NULL;
    Buffer *cert = NULL;
    char *cert_string = NULL;

    error_msg[0] =0;
    *error_code=0; //assume undefined

    PRUint64 snum = DER_GetInteger(&(i_cert)->serialNumber);
    RA::Debug("RA_Enroll_Processor::DoRenewal", "begins renewal for serial number %u with profileId=%s", (int)snum, profileId);

    certRenewal = new CertEnroll();
    cert = certRenewal->RenewCertificate(snum, connid, profileId, error_msg);

    if (error_msg[0] != 0) { // We can assume a non grace period error here.
        *error_code = 1;
    }
// this is where renewal happens .. audit log for fail/ success here? 
    if (cert == NULL) {
        r = false;
        RA::Debug("RA_Enroll_Processor::DoRenewal", "Renewal failed for serial number %d", snum);
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        goto loser;
    }
    RA::Debug("RA_Enroll_Processor::DoRenewal", "Renewal suceeded for serial number %d", snum);

    cert_string = (char *) cert->string();
    *o_cert = CERT_DecodeCertFromPackage((char *) cert_string, 
      (int) cert->size());
    if (o_cert != NULL) {
        char msg[2048];
        RA::ra_tus_print_integer(msg, &(o_cert[0])->serialNumber);
        RA::Debug("DoRenewal", "Received newly issued Certificate");
        RA::Debug("DoRenewal serial=", msg);
        RA::Debug("DoRenewal", "yes");
    } else {
        r = false;
    }
    free(cert_string);

loser:
    if( certRenewal != NULL ) {
        delete certRenewal;
        certRenewal = NULL;
    }
    if( cert != NULL ) {
        delete cert;
        cert = NULL;
    }
    return r;
}

#define RENEWAL_FAILURE 1
#define RENEWAL_FAILURE_GRACE 2

/*
* Renewal logic
*  1. Create Optional local TPS grace period per token profile, 
*     per token type, such as signing or encryption.
*    This grace period must match how the CA is configured. Ex:
*    op.enroll.userKey.renewal.encryption.enable=true
*    op.enroll.userKey.renewal.encryption.gracePeriod.enable=true
*    op.enroll.userKey.renewal.encryption.gracePeriod.before=30
*    op.enroll.userKey.renewal.encryption.gracePeriod.after=30
*  2. In case of a grace period failure the code will go on 
*     and attempt to renew the next certificate in the list.
*  3. In case of any other code failure, the code will abort
*     and leave the token untouched, while informing the user
*     with an error message.
*
*
*/
bool RA_Enroll_Processor::ProcessRenewal(AuthParams *login, RA_Session *session, char **&ktypes,
 char **&origins,
  char *tokenType, PKCS11Obj *pkcs11objx, int pkcs11obj_enable,
  Secure_Channel *channel,
  const char *cuid, char *msn,
  const char *final_applet_version, const char *userid,
  RA_Status &o_status, CERTCertificate **&certificates,
  int &o_certNums, char **&tokenTypes)
{
    bool r = true;
    o_status = STATUS_ERROR_RENEWAL_IS_PROCESSED;
    char keyTypePrefix[256];
    char configname[256];
    char filter[256];
    LDAPMessage *result = NULL;
    const char *pretty_cuid = NULL;
    char audit_msg[512] = "";
    char *keyVersion = NULL;
    int renewal_failure_found = 0;
   
    int   maxCertUpdate = 25; 
    char  *renewedCertUpdateList[25];
    int   renewedCertUpdateCount = 0;
    int renew_error = 0;

    int i = 0;
    const char *FN="RA_Enroll_Processor::ProcessRenewal";

    RA::Debug("RA_Enroll_Processor::ProcessRenewal", "starts");

    // get key version for audit logs
    if (channel != NULL) {
        if( keyVersion != NULL ) {
            PR_Free( (char *) keyVersion );
            keyVersion = NULL;
        }
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    // e.g. op.enroll.userKey.renewal.keyType.num
    // renewal params will just have to match that of the previous
    // enrollment tps profile. Will try to be smarter later...
    PR_snprintf(configname, 256, "op.enroll.%s.renewal.keyType.num",
      tokenType);
    int keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname, -1);
    if (keyTypeNum == -1) {
        RA::Debug("RA_Enroll_Processor::ProcessRenewal", "Missing the configuration parameter for %s", configname);
        r = false;
        o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        PR_snprintf(audit_msg, 512, "Missing the configuration parameter for %s", configname);
        goto loser;
    }

    RA::Debug("RA_Enroll_Processor::ProcessRenewal", "keyType.num=%d", keyTypeNum);

    o_certNums = keyTypeNum;
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * keyTypeNum);
    ktypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    origins = (char **) malloc (sizeof(char *) * keyTypeNum);
    tokenTypes = (char **) malloc (sizeof(char *) * keyTypeNum);

    for (i=0; i<keyTypeNum; i++) {
        certificates[i] = NULL;
        ktypes[i] = NULL;
        origins[i] = NULL;
        tokenTypes[i] = NULL;
    }
    
    for (i=0; i<keyTypeNum; i++) {
        bool renewable = true;
        // e.g. op.enroll.userKey.renewal.keyType.value.0=signing
        // e.g. op.enroll.userKey.renewal.keyType.value.1=encryption
        PR_snprintf(configname, 256, "op.enroll.%s.renewal.keyType.value.%d", tokenType, i);
        const char *keyTypeValue = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));

        if (keyTypeValue == NULL) {
            RA::Debug("RA_Enroll_Processor::ProcessRenewal",
              "Missing the configuration parameter for %s", configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            PR_snprintf(audit_msg, 512, "Missing the configuration parameter for %s", configname);
            goto loser;
        }
        RA::Debug("RA_Enroll_Processor::ProcessRenewal", "keyType == %s ", keyTypeValue);
        TokenKeyType key_type = KEY_TYPE_ENCRYPTION;
        if (strcmp(keyTypeValue, "signing") == 0)
          key_type = KEY_TYPE_SIGNING;
        else if (strcmp(keyTypeValue, "encryption") == 0) 
          key_type = KEY_TYPE_ENCRYPTION;
        else
          key_type = KEY_TYPE_SIGNING_AND_ENCRYPTION;

        // e.g. op.enroll.userKey.renewal.signing.enable=true
        PR_snprintf(configname, 256, "op.enroll.%s.renewal.%s.enable", tokenType, keyTypeValue);
        renewable = RA::GetConfigStore()->GetConfigAsBool(configname);

        if (!renewable) {
           RA::Debug("RA_Enroll_Processor::ProcessRenewal", "renewal not enabled");
           continue;
        }

        // set allowable $$ config patterns
        NameValueSet nv;
        pretty_cuid = GetPrettyPrintCUID(cuid);

        nv.Add("pretty_cuid", pretty_cuid);
        nv.Add("cuid", cuid);
        nv.Add("msn", msn);
        nv.Add("userid", userid);
        //nv.Add("profileId", profileId);

        /* populate auth parameters output to nv also */
        /* so we can reference to the auth parameter by */
        /* using $auth.cn$, or $auth.mail$ */
        if (login != NULL) {
          int s = login->Size();
          for (int x = 0; x < s; x++) {
             char namebuf[2048];
             char *name = login->GetNameAt(x);
             sprintf(namebuf, "auth.%s", name);
             nv.Add(namebuf, login->GetValue(name));
          }
        }

        /*
         * Get certs from the tokendb for this token to find out about
         * renewal possibility
         */


            RA::Debug("RA_Enroll_Processor::ProcessRenewal", "Renew the certs for %s", keyTypeValue);
            PR_snprintf(filter, 256, "(&(tokenKeyType=%s)(tokenID=%s))",
              keyTypeValue, cuid);       
            int rc = RA::ra_find_tus_certificate_entries_by_order_no_vlv(filter,
              &result, 1);
 
            tokenTypes[i] = PL_strdup(tokenType);
            if (rc == LDAP_SUCCESS) {
                bool renewed = false;
                const char *caconnid;
                const char *profileId;
                PR_snprintf(keyTypePrefix, 256, "op.enroll.%s.keyGen.%s", tokenType,keyTypeValue);
                PR_snprintf(configname, 256, "op.enroll.%s.renewal.%s.enable", tokenType, keyTypeValue);
                PR_snprintf((char *)configname, 256,"op.enroll.%s.renewal.%s.certId", tokenType, keyTypeValue);
                char *certId = (char *)RA::GetConfigStore()->GetConfigAsString(configname, "C0");
                PR_snprintf((char *)configname, 256, "op.enroll.%s.renewal.%s.certAttrId", tokenType, keyTypeValue);
                char *certAttrId = (char *)RA::GetConfigStore()->GetConfigAsString(configname, "c0");
                //PR_snprintf((char *)configname, 256, "%s.privateKeyAttrId", keyTypePrefix);
                //const char *priKeyAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "k0");
                //PR_snprintf((char *)configname,  256,"%s.publicKeyAttrId", keyTypePrefix);
                //const char *pubKeyAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "k1");
                RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                  "certId=%s, certAttrId=%s",certId, certAttrId);

                char finalCertId[3];
                char finalCertAttrId[3];

                finalCertId[0] = certId[0];
                finalCertId[1] = certId[1];
                finalCertId[2] = 0;

                finalCertAttrId[0] = certAttrId[0];
                finalCertAttrId[1] = certAttrId[1];
                finalCertAttrId[2] = 0;

                LDAPMessage *e= NULL;
                char *attr_status = NULL;
                for( e = RA::ra_get_first_entry( result );
                       e != NULL;
                       e = RA::ra_get_next_entry( e ) ) {
                    attr_status = RA::ra_get_cert_status( e );
                    if( (strcmp( attr_status, "revoked" ) == 0) ||
                        (strcmp( attr_status, "renewed" ) == 0) ) {
                        if (attr_status != NULL) {
                            PL_strfree(attr_status);
                            attr_status = NULL;
                        }
                        continue;
                    }

                    const char *label= NULL;
                    const char *pattern= NULL;
                    Buffer *certbuf = NULL;

                    // retrieve the most recent certificate to start

                    CERTCertificate **certs = RA::ra_get_certificates(e);
                    CERTCertificate *o_cert = NULL;
                    SECKEYPublicKey *pk_p = NULL;
                    SECItem si_mod;
                    Buffer *modulus=NULL;
                    SECItem *si_kid = NULL;
                    Buffer *keyid=NULL;
                    SECItem si_exp;
                    Buffer *exponent=NULL;
                    CERTSubjectPublicKeyInfo*  spkix = NULL;

                    bool graceEnabled = false;
                    int graceBefore = 0;
                    int graceAfter = 0;

                    if (certs[0] != NULL) {

                        RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                          "Certificate to check for renew");

                        // check if renewable (note: CA makes the final decision)
                        /* testing...pass through for now
                        if (!isCertRenewable(certs[0])) {
                            RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                                "Cert outside of renewal period");
                            r = false;
                            goto rloser;
                        }
                        */

                        // op.enroll.userKey.renewal.signing.ca.conn
                        // op.enroll.userKey.renewal.encryption.ca.conn
                        PR_snprintf(configname, 256, 
                          "op.enroll.%s.renewal.%s.ca.conn", tokenType, keyTypeValue);
                        caconnid = RA::GetConfigStore()->GetConfigAsString(configname);
                        if (caconnid == NULL) {
                            RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                              "Missing the configuration parameter for %s", configname);
                              r = false;
                            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
                            PR_snprintf(audit_msg, 512, "Missing the configuration parameter for %s", configname);
                            goto rloser;
                        }
                        
                        // op.enroll.userKey.renewal.signing.ca.profileId
                        // op.enroll.userKey.renewal.encryption.ca.profileId
                        PR_snprintf(configname, 256, 
                          "op.enroll.%s.renewal.%s.ca.profileId", tokenType, keyTypeValue);
                        profileId = RA::GetConfigStore()->GetConfigAsString(configname);
                        if (profileId == NULL) {
                            RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                              "Missing the configuration parameter for %s", configname);
                              r = false;
                            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
                            PR_snprintf(audit_msg, 512, "Missing the configuration parameter for %s", configname);
                            goto rloser;
                        }

                        RA::Debug("RA_Enroll_Processor::ProcessRenewal","got profileId=%s",profileId);
			RA::Debug("RA_Enroll_Processor::ProcessRenewal", "begin renewal");


                        PR_snprintf(configname,256,
                           "op.enroll.%s.renewal.%s.gracePeriod.enable",tokenType,keyTypeValue);

                        graceEnabled = RA::GetConfigStore()->GetConfigAsBool(configname,0);

                        if(graceEnabled) {

                            PR_snprintf(configname,256,
                               "op.enroll.%s.renewal.%s.gracePeriod.before",tokenType,keyTypeValue);

                            graceBefore = RA::GetConfigStore()->GetConfigAsInt(configname,0);

                            PR_snprintf(configname,256,
                                "op.enroll.%s.renewal.%s.gracePeriod.after",tokenType,keyTypeValue); 
                            
                            graceAfter = RA::GetConfigStore()->GetConfigAsInt(configname,0); 
                            // check if renewable (note: CA makes the final decision)
                            if (!isCertRenewable(certs[0],graceBefore,graceAfter)) {
                                RA::Debug("RA_Enroll_Processor::ProcessRenewal",
                                    "Cert outside of renewal period");
                                renewal_failure_found = RENEWAL_FAILURE_GRACE;
                                //Since this is merely a grace period failure for one cert
                                //let's keep going.
                                r = true;
                                goto rloser;
                            }

                        }

                        // send renewal request to CA
                        // o_cert is the cert gotten back
                        r = DoRenewal(caconnid, profileId, certs[0], &o_cert, audit_msg, &renew_error);
                        if (r == false) {
			    RA::Debug("RA_Enroll_Processor::ProcessRenewal", "after DoRenewal failure. o_cert %p renew_error %d",o_cert,renew_error);
                            o_status = STATUS_ERROR_MAC_ENROLL_PDU;
                            //Assume a renewal grace failure here since we can't obtain the reason.
                            //This is the most likely error and there is a chance the next renewal may succeed.
                            if ( renew_error == 0) { //Assume undefined error is error coming from CA
                                renewal_failure_found = RENEWAL_FAILURE_GRACE;
                            } else {
                                renewal_failure_found = RENEWAL_FAILURE;
                            }
                            char snum[2048];
                            RA::ra_tus_print_integer(snum, &(certs[0])->serialNumber);
                            RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC_CERT_REQ, 
                              userid, cuid, msn, "failure", "renewal", final_applet_version,
                              keyVersion != NULL ? keyVersion :  "", 
                              snum, caconnid, audit_msg);
                            //Since this is merely a grace period or renewal failure for one cert
                            //let's keep it going

                            if (renew_error == 0) { //undefined error means probably grace period, forgive that.
                                r = true;
                            }
                            goto rloser;
                        }

                        // got cert... 

                        // build label
                        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label",
	                    OP_PREFIX, tokenType, keyTypeValue);
                        RA::Debug(LL_PER_CONNECTION,FN,
		                "label '%s'", configname);
                        pattern = RA::GetConfigStore()->GetConfigAsString(configname);

                        if(pattern == NULL)
                        {
                            RA::Debug("RA_Enroll_Processor::ProcessRenewal", "no configured cert label!");
                            renewal_failure_found = RENEWAL_FAILURE;
                            PR_snprintf(audit_msg,512, "No cert label configured for cert!");
                            goto rloser;
                        }

                        RA::Debug(LL_PER_CONNECTION,FN,
                                "pattern '%s'",pattern);

			label = MapPattern(&nv, (char *) pattern);

                        RA::Debug(LL_PER_CONNECTION,FN,
                                "label '%s'",label);

			if (o_cert != NULL) {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "got cert!!");
//			  tmp_c = NSSBase64_EncodeItem(0, 0, 0, &(o_cert)->derCert);
//			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "after NSSBase64_EncodeItem");

                          char snum[2048];
                          RA::ra_tus_print_integer(snum, &o_cert->serialNumber);
                          RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC_CERT_REQ, 
                            userid, cuid, msn, "success", "renewal", final_applet_version, 
                            keyVersion != NULL ? keyVersion :  "", 
                            snum, caconnid, "certificate renewed");
			} else {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "no cert!!");
                          PR_snprintf(audit_msg, 512, "No cert returned from DoRenewal");
			  goto rloser;
			}

                        ktypes[i] = PL_strdup(keyTypeValue);
                        origins[i] = PL_strdup(cuid);
                        certificates[i] = o_cert;
                        //o_certNums++;

                        // For the encrytion cert we actually need to calculate the proper certId and certAttrId
                        // since we now leave previous encryption certs on the token to allow dencryption of old
                        // Emails by the user.
             
                        if( key_type == KEY_TYPE_ENCRYPTION) {

                            int new_cert_id = GetNextFreeCertIdNumber(pkcs11objx);

                            RA::Debug("RA_Enroll_Processor::ProcessRenewal", 
                                "Encryption cert, calculated new cert id: %d",new_cert_id);

                            //Is the calculated cert id reasonable based on the current state of the
                            // token and the expected renewal configuration.
                            if( !(new_cert_id  > keyTypeNum ) || new_cert_id > 9) {
                                RA::Debug(LL_PER_CONNECTION,FN,
                                    "RA_Enroll_Processor::ProcessRenewal","Possible misconfiguration or out of sync token!");
                                PR_snprintf(audit_msg, 512, "Renewal of cert failed, misconfiguration or out of sync token!");
                                renewal_failure_found = RENEWAL_FAILURE; 
                                goto rloser;

                            }

                            finalCertId[0]= 'C';
                            finalCertId[1] = '0' + new_cert_id;
                       
                            finalCertAttrId[0] = 'c';
                            finalCertAttrId[1] = '0' + new_cert_id;

                            RA::Debug(LL_PER_CONNECTION,FN,
                                 "finalCertId %s finalCertAttrId %s", finalCertId, finalCertAttrId);
                        }

                        // write certificate to token
			certbuf = new Buffer(o_cert->derCert.data, o_cert->derCert.len);
                        if (pkcs11obj_enable)
			{
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (finalCertId[0] << 24) +
							   (finalCertId[1] << 16),
							   certbuf);
			  pkcs11objx->AddObjectSpec(objSpec);
			} else {
                          RA::Debug(LL_PER_CONNECTION,FN,
                            "Not implemented");
                          renewal_failure_found = RENEWAL_FAILURE;
                          PR_snprintf(audit_msg, 512, "Write cert to token failed: pkcs11obj_enable = false not implemented");
                          goto rloser;
/*
                          RA::Debug(LL_PER_CONNECTION,FN,
                                 "About to create certificate object on token");
                          rc = channel->CreateCertificate(certId, certbuf);
                          if (rc == -1) {
                                 RA::Error(LL_PER_CONNECTION,FN,
                                 "Failed to create certificate object on token");

                                 o_status = STATUS_ERROR_MAC_ENROLL_PDU;
                                 goto rloser;
                          }
*/
                        }

                        if (o_cert->subjectKeyID.data != NULL) {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "subjectKeyID found in cert");
//later, add code to check if keys really exist on token!
                          keyid = new Buffer((BYTE*)o_cert->subjectKeyID.data,
                                    (unsigned int)o_cert->subjectKeyID.len);

                        } else {// should always have keyid
//use existing original keyid
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "no subjectKeyID found in cert, use existing");
                          keyid = new Buffer((BYTE*)certs[0]->subjectKeyID.data,
                                    (unsigned int)certs[0]->subjectKeyID.len);
                        }

                        if (pkcs11obj_enable)
			{
			  Buffer b = channel->CreatePKCS11CertAttrsBuffer(
                               key_type , finalCertAttrId, label, keyid);
                          if (b == NULL) {
                              PR_snprintf(audit_msg, 512, "Write cert to token failed: CreatePKCS11CertAttrsBuffer returns null");
                              renewal_failure_found = RENEWAL_FAILURE;
                              goto rloser;
                          }
                          ObjectSpec *objSpec = 
                              ObjectSpec::ParseFromTokenData(
				   (finalCertAttrId[0] << 24) +
				   (finalCertAttrId[1] << 16),
				   &b);
                          if (objSpec == NULL) {
                              PR_snprintf(audit_msg, 512, "Write cert to token failed: ParseFromTokenData returns null");
                              renewal_failure_found = RENEWAL_FAILURE;
                              goto rloser;
                          }

                          //We need to massage the fixedAttributes of this object to allow the CKA_ID value
                          //of the original encryption cert to be available for coolkey to read.
                          // Coolkey only deals in a one byte index 0 - n, ex: "01".
                          // Coolkey uses the final byte of the "fixedAttributes" property of each object
                          // to identify the object. This value needs to be the same for each cert and its
                          // corresponding key pair. See ObjectSpec::ParseAttributes.

                          if (key_type == KEY_TYPE_ENCRYPTION) {

                             unsigned long currentFixedAttributes = objSpec->GetFixedAttributes();
                             unsigned long modifiedFixedAttributes = currentFixedAttributes;

                             // Here we want the original encryption cert's id number.
                             int val = (certId[1] - '0');

                             modifiedFixedAttributes &= (BYTE) 0xFFFFFFF0;
                             modifiedFixedAttributes |=  (BYTE) val;
                             objSpec->SetFixedAttributes(modifiedFixedAttributes);
 
                             RA::Debug("RA_Enroll_Processor::ProcessRenewal", 
                                 "original fixed Attributes %lu  modified ones %lu",
                                 currentFixedAttributes,modifiedFixedAttributes);  
                          }

			  pkcs11objx->AddObjectSpec(objSpec);
			} else {
                          RA::Debug(LL_PER_CONNECTION,FN,
                            "Not implemented");
                          PR_snprintf(audit_msg, 512, "Write cert to token failed: pkcs11obj_enable = false not implemented");
                          renewal_failure_found = RENEWAL_FAILURE;
                          goto rloser;
/*
                          RA::Debug(LL_PER_CONNECTION,FN,
                                  "About to create PKCS#11 certificate Attributes");
                          rc = channel->CreatePKCS11CertAttrs(keyTypeValue, certAttrId, label, keyid);
                          if (rc == -1) {
                           RA::Error(LL_PER_CONNECTION,FN,
                                  "PKCS11 Certificate attributes creation failed");
                                  o_status = STATUS_ERROR_MAC_ENROLL_PDU;
                                  goto rloser;
                          }
*/
                        }

                        spkix = &(o_cert->subjectPublicKeyInfo);
                        if (spkix == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: subjectPublicKeyInfo is null");
                            goto rloser;
                        }
                        pk_p = SECKEY_ExtractPublicKey(spkix);
                        if (pk_p == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: ExtractPublicKey is null");
                            goto rloser;
                        }
                        SECKEY_DestroySubjectPublicKeyInfo(spkix);

			/* fill in keyid, modulus, and exponent */

			si_mod = pk_p->u.rsa.modulus;
			modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);
                        if (modulus == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: modulus is null");
                            renewal_failure_found = RENEWAL_FAILURE;
                            goto rloser;
                        }
			spkix = SECKEY_CreateSubjectPublicKeyInfo(pk_p);
                        if (spkix == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: CreateSubjectPublicKeyInfo returns null");
                            renewal_failure_found = RENEWAL_FAILURE;
                            goto rloser;
                        }

			/* 
			 * RFC 3279
			 * The keyIdentifier is composed of the 160-bit SHA-1 hash of the
			 * value of the BIT STRING subjectPublicKey (excluding the tag,
			 * length, and number of unused bits).
			 */
			spkix->subjectPublicKey.len >>= 3;
			si_kid = PK11_MakeIDFromPubKey(&spkix->subjectPublicKey);
                        if (si_kid == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: si_kid is null");
                            renewal_failure_found = RENEWAL_FAILURE;
                            goto rloser;
                        }
			spkix->subjectPublicKey.len <<= 3;
			SECKEY_DestroySubjectPublicKeyInfo(spkix);

                        if (keyid == NULL)
			    keyid = new Buffer((BYTE*) si_kid->data, si_kid->len);
                        if (keyid == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: keyid is null");
                            renewal_failure_found = RENEWAL_FAILURE;
                            goto rloser;
                        }
			si_exp = pk_p->u.rsa.publicExponent;
			exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);
                        if (exponent == NULL) {
                            PR_snprintf(audit_msg, 512, "Write cert to token failed: exponent is null");
                            renewal_failure_found = RENEWAL_FAILURE;
                            goto rloser;
                        }
			RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
              "Keyid, modulus and exponent have been extracted from public key");

                        renewed = true;

                        RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC,
                          userid != NULL ? userid : "",
                          cuid != NULL ? cuid : "",
                          msn != NULL ? msn : "",
                          "success",
                          "renewal",
                          final_applet_version != NULL ? final_applet_version : "",
                          keyVersion != NULL? keyVersion : "",
                          "Cert written to token successfully");


		    rloser:

                        if( keyid != NULL ) {
                          delete keyid;
                          keyid = NULL;
                        }
			if( label != NULL ) {
			  PL_strfree( (char *) label );
			  label = NULL;
			}
                        if(renewal_failure_found == RENEWAL_FAILURE) {
                            RA::Debug("RA_Enroll_Processor_ProcessRenewal", "A renewal in list failed other than grace period error, aborting.");
                            goto loser;
                        }
                    }
                    break;
                  } //for
                  if((strcmp( attr_status, "active" ) == 0) &&
                       renewed) {
                      char *cn = RA::ra_get_cert_cn(e);
                      if(renewedCertUpdateCount < ( maxCertUpdate -1)) //unlikely scenario this fails 
                          renewedCertUpdateList[renewedCertUpdateCount++] = PL_strdup(cn);
                      // Let's hold off on the celebration until the end.
                      // RA::ra_update_cert_status(cn, "renewed");
                      if (cn != NULL) {
                          PL_strfree(cn);
                          cn = NULL;
                      }
                  }
                  if( attr_status != NULL ) {
                      PL_strfree( attr_status );
                      attr_status = NULL;
                  }
            } else {
	      r = false;
	      o_status = STATUS_ERROR_LDAP_CONN;
	      goto loser;
            }
            RA::Debug("RA_Enroll_Processor::ProcessRenewal", 
		      "Filter to find certificates = %s", filter);
    }

loser:
    if (strlen(audit_msg) > 0) { // a failure occurred
        RA::Audit(EV_RENEWAL, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "failure",
          "renewal",
          final_applet_version != NULL ? final_applet_version : "",
          keyVersion != NULL? keyVersion : "",
          audit_msg);
    }

    //Let's wait until all the certs are processed to actually update the renewal status
    RA::Debug("RA_Enroll_Process::ProcessRenewal","renewedCertUpdateCount %d", renewedCertUpdateCount);
    if(renewedCertUpdateCount > 0) {
        for(int rr = 0; rr < renewedCertUpdateCount; rr++) {
            if(renewedCertUpdateList[rr]) {
                if(renewal_failure_found != RENEWAL_FAILURE) {
                    RA::Debug("RA_Enroll_Process::ProcessRenewal","updating to renewed status of cn= %s", renewedCertUpdateList[rr]);
                    RA::ra_update_cert_status(renewedCertUpdateList[rr],"renewed");
                }
                PL_strfree(renewedCertUpdateList[rr]);
                renewedCertUpdateList[rr] = NULL;
            }
        }
    } else {
        // All certs failed to renew 
         RA::Debug("RA_Enroll_Process::ProcessRenewal","All certs failed to renew, bailing with error");
        o_status =  STATUS_ERROR_MAC_ENROLL_PDU;
        r = false;

    }

    if( pretty_cuid != NULL ) {
        PR_Free( (char *) pretty_cuid );
        pretty_cuid = NULL;
    }
    if( result != NULL ) {
        ldap_msgfree( result );
    }
  
    if( keyVersion != NULL ) {
        PR_Free( (char *) keyVersion );
        keyVersion = NULL;
    }

    return r;
}

bool RA_Enroll_Processor::ProcessRecovery(AuthParams *login, char *reason, RA_Session *session, char **&origins, char **&ktypes,
  char *tokenType, PKCS11Obj *pkcs11objx, int pkcs11obj_enable,
  NameValueSet *extensions, Secure_Channel *channel, Buffer *wrapped_challenge,
  Buffer *key_check, Buffer *plaintext_challenge, char *cuid, char *msn,
  const char *final_applet_version, char *khex, const char *userid,
  RA_Status &o_status, CERTCertificate **&certificates, char *lostTokenCUID,
  int &o_certNums, char **&tokenTypes, char *origTokenType)
{
    bool r = true;
    o_status = STATUS_ERROR_RECOVERY_IS_PROCESSED;
    char keyTypePrefix[256];
    char configname[256];
    char filter[256];
    LDAPMessage *result = NULL;
    LDAPMessage *e = NULL;
    char *o_pub = NULL;
    char *o_priv = NULL;
    const char *connid = NULL;
    bool tksServerKeygen = false;
    bool serverKeygen = false;
    bool archive = false;
    const char *pretty_cuid = NULL;
    char audit_msg[512] = "";
    char *keyVersion = NULL;
    char *ivParam = NULL;

    int i = 0;
    int totalNumCerts = 0;
    int actualCertIndex = 0; 
    int legalScheme = 0;
    int isGenerateandRecover = 0;
    const char *FN="RA_Enroll_Processor::ProcessRecovery";

    bool isECC = false;
    BYTE algorithm;
    CERTSubjectPublicKeyInfo*  spkix = NULL;
    SECKEYECParams  *eccParams = NULL;
    SECKEYPublicKey *pk_p = NULL;

    RA::Debug("RA_Enroll_Processor::ProcessRecovery","entering...");
    // get key version for audit logs
    if (channel != NULL) {
        if( keyVersion != NULL ) {
            PR_Free( (char *) keyVersion );
            keyVersion = NULL;
        }
        keyVersion = Util::Buffer2String(channel->GetKeyInfoData());
    }

    PR_snprintf(configname, 256, "op.enroll.%s.keyGen.recovery.%s.keyType.num",
      tokenType, reason);
    int keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname, -1);
    if (keyTypeNum == -1) {
        RA::Debug("RA_Enroll_Processor::ProcessRecovery", "Missing the configuration parameter for %s", configname);
        r = false;
        o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        goto loser;
    }

    PR_snprintf((char *)configname, 256, "op.enroll.%s.keyGen.encryption.alg", tokenType);
    //Default RSA_CRT=2
    algorithm = (BYTE) RA::GetConfigStore()->GetConfigAsInt(configname, 2);
    isECC = RA::isAlgorithmECC(algorithm);
    if (isECC) {
        RA::Debug("RA_Enroll_Processor::ProcessRecovery", "algorithm is ECC");
    } else {
        RA::Debug("RA_Enroll_Processor::ProcessRecovery", "algorithm is not ECC");
    }

    //We will have to rifle through the configuration to see if there any recovery operations with
    //scheme "GenerateNewKeyandRecoverLast" which allows for recovering the old key AND generating a new
    // one for the encryption type only. If this scheme is present, the number of certs for bump by
    // 1 for each occurance.

    totalNumCerts = 0;
    for(i = 0; i<keyTypeNum; i++) {
        PR_snprintf(configname, 256, "op.enroll.%s.keyGen.recovery.%s.keyType.value.%d", tokenType, reason, i);
        const char *keyTypeValue = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));

        if (keyTypeValue == NULL) {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery",
              "Missing the configuration parameter for %s", configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            goto loser;
        }
        PR_snprintf(configname, 256, "op.enroll.%s.keyGen.%s.recovery.%s.scheme", tokenType, keyTypeValue, reason);
        char *scheme = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));
        if (scheme == NULL) {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery",
            "Missing the configuration parameter for %s", configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            goto loser;
        }

        //If we are doing "GenerateNewKeyandRecoverLast, we will create two certificates
        //for that particular round.
        if(PL_strcasecmp(scheme, "GenerateNewKeyandRecoverLast") == 0) {

            //Make sure someone doesn't try "GenerateNewKeyandRecoverLast" with a signing key.

            if(PL_strcasecmp(keyTypeValue,"encryption" ) != 0) {
                 RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                 "Invalid config param for %s. Can't use GenerateNewKeyandRecoveLaste scheme with non encryption key",
                 configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            goto loser;
            }
            totalNumCerts ++;
        }
        totalNumCerts ++;
    }

    RA::Debug("RA_Enroll_Processor::ProcessRecovery","totalNumCerts %d ",totalNumCerts);
    RA::Debug("RA_Enroll_Processor::ProcessRecovery", "keyTypenum=%d", keyTypeNum);


    if(!(totalNumCerts > keyTypeNum)) {
        totalNumCerts = keyTypeNum;
    }

    o_certNums = totalNumCerts;
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * totalNumCerts);
    ktypes = (char **) malloc (sizeof(char *) * totalNumCerts);
    origins = (char **) malloc (sizeof(char *) * totalNumCerts);
    tokenTypes = (char **) malloc (sizeof(char *) * totalNumCerts);

    for(i = 0; i < totalNumCerts; i++) {
        ktypes[i] = NULL;
        origins[i] = NULL;
        tokenTypes[i] = NULL;
        certificates[i] = NULL;
    }

    //Iterate through number of key types. Iteration will be modified in case we have to insert extra
    //certificates due to the "GenerateNewKeyandRecoverLast" scheme.

    actualCertIndex = 0;
    legalScheme = 0;
    for (i=0; i<keyTypeNum; i++) {
         RA::Debug("RA_Enroll_Processor::ProcessRecovery","Top cert loop: i %d actualCertIndex %d",i,actualCertIndex);
        PR_snprintf(configname, 256, "op.enroll.%s.keyGen.recovery.%s.keyType.value.%d", tokenType, reason, i);
        const char *keyTypeValue = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));

        RA::Debug("RA_Enroll_Processor::ProcessRecovery", "keyType == %s ", keyTypeValue);

        if (keyTypeValue == NULL) {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery",
              "Missing the configuration parameter for %s", configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            goto loser;
        }
        PR_snprintf(configname, 256, "op.enroll.%s.keyGen.%s.recovery.%s.scheme", tokenType, keyTypeValue, reason);
        char *scheme = (char *)(RA::GetConfigStore()->GetConfigAsString(configname));
        if (scheme == NULL) {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery",
            "Missing the configuration parameter for %s", configname);
            r = false;
            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
            goto loser;
        }

        // set allowable $$ config patterns
        NameValueSet nv;
        pretty_cuid = GetPrettyPrintCUID(cuid);

        nv.Add("pretty_cuid", pretty_cuid);
        nv.Add("cuid", cuid);
        nv.Add("msn", msn);
        nv.Add("userid", userid);
        //nv.Add("profileId", profileId);

        /* populate auth parameters output to nv also */
        /* so we can reference to the auth parameter by */
        /* using $auth.cn$, or $auth.mail$ */
        if (login != NULL) {
          int s = login->Size();
          for (int x = 0; x < s; x++) {
             char namebuf[2048];
             char *name = login->GetNameAt(x);
             sprintf(namebuf, "auth.%s", name);
             nv.Add(namebuf, login->GetValue(name));
          }
        }
        //Check for the special scheme where we generate a new cert and 
        //recover the last one.

        if(PL_strcasecmp(scheme, "GenerateNewKeyandRecoverLast") == 0)  {
            isGenerateandRecover = 1;
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
                "Scheme %s: GenerateNewKeyandRecoverLast case!",scheme); 
        } else {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
                "Scheme %s: Not GenerateNewKeyandRecoverLast case!",scheme);
            isGenerateandRecover = 0;
        }
        
        if ((PL_strcasecmp(scheme, "GenerateNewKey") == 0) || isGenerateandRecover) {
            legalScheme = 1;
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", "Generate new key for %s", keyTypeValue);
            r = GenerateCertificate(login, keyTypeNum, keyTypeValue, actualCertIndex, session, origins, ktypes, tokenType,
              pkcs11objx, pkcs11obj_enable, extensions, channel, wrapped_challenge,
              key_check, plaintext_challenge, cuid, msn, final_applet_version,
              khex, userid, o_status, certificates);
            tokenTypes[actualCertIndex] = PL_strdup(tokenType);
            if (o_status == STATUS_NO_ERROR)
                o_status = STATUS_ERROR_RECOVERY_IS_PROCESSED;
        } 

        if ((PL_strcasecmp(scheme, "RecoverLast") == 0) || isGenerateandRecover) {
            RA::Debug("RA_Enroll_Processor::RecoverLast", "Recover the key for %s", keyTypeValue);
            // Special case for GenerateandRecover scenario.

            legalScheme = 1;
            if(isGenerateandRecover) {
                RA::Debug("RA_Enroll_Processor::RecoverLast", 
                    "Generate extra recoverd cert for GenerateNewKeyandRecoverLast");

                actualCertIndex ++;
            }
            PR_snprintf(filter, 256, "(&(tokenKeyType=%s)(tokenID=%s))",
              keyTypeValue, lostTokenCUID);       
            int rc = RA::ra_find_tus_certificate_entries_by_order_no_vlv(filter,
              &result, 1);
 
            tokenTypes[actualCertIndex] = PL_strdup(origTokenType);
            char **attr = (char **) malloc (sizeof(char *) * totalNumCerts);
            if (rc == LDAP_SUCCESS) {
                // retrieve the most recent certificate, we just recover the most
                // recent one
                e = RA::ra_get_first_entry(result);
                if (e != NULL) {
                    CERTCertificate **certs = RA::ra_get_certificates(e);
                    if (certs[0] != NULL) {
                        RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                          "Certificate used to restore the private key");
                        PR_snprintf(configname, 256, 
                          "op.enroll.%s.keyGen.%s.serverKeygen.drm.conn", tokenType, keyTypeValue);
                        const char *drmconnid = RA::GetConfigStore()->GetConfigAsString(configname);
                        if (drmconnid == NULL) {
                            RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                              "Missing the configuration parameter for %s", configname);
                              r = false;
                            o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
                            PR_snprintf(audit_msg, 512, "Key Recovery failed. Missing the configuration parameter for %s", configname);
                            goto loser;
                        }
       
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "begin recovery code");

			SECItem si_mod;
			Buffer *modulus=NULL;
			SECItem *si_kid = NULL;
			Buffer *keyid=NULL;
			SECItem si_exp;
			Buffer *exponent=NULL;
            CERTSubjectPublicKeyInfo*  spki = NULL;

                        //Now we have to get the original config params for the encryption cert and keys

                        //XXX these attr functions shouldn't take config params
                        PR_snprintf(keyTypePrefix, 256, "op.enroll.%s.keyGen.encryption", tokenType);

                        PR_snprintf((char *)configname, 256, "%s.keySize", keyTypePrefix);
                        int keysize = RA::GetConfigStore()->GetConfigAsInt(configname, 1024);

                        PR_snprintf((char *)configname, 256, "%s.keyUsage", keyTypePrefix);
                        int keyUsage = RA::GetConfigStore()->GetConfigAsInt(configname, 0);
                        PR_snprintf((char *)configname, 256, "%s.keyUser", keyTypePrefix);
                        int keyUser = RA::GetConfigStore()->GetConfigAsInt(configname, 0);

                        PR_snprintf((char *)configname, 256, "%s.certId",keyTypePrefix);

                        const char *origCertId = RA::GetConfigStore()->GetConfigAsString(configname, "C0");
 
                        //actually adjust the crucial values based on this extra certificate
                        //being generated.

                        int highestCertId = 0;
                        int newCertId = 0;
                        if(isGenerateandRecover) {
                           //find highest cert id number.
                           for(int j=0; j < keyTypeNum; j++) {
                               PR_snprintf((char *)configname, 256,"%s.certId", keyTypePrefix); 
                               const char *cId = RA::GetConfigStore()->GetConfigAsString(configname, "C0");
                               int id_int = 0;
                               if(cId)  {
                                   id_int = cId[1] - '0';
                               }

                               if (id_int > highestCertId)
                                   highestCertId = id_int;
                           }
                           highestCertId++; 
                        } else {
                           highestCertId = origCertId[1] - '0';
                        }

                        newCertId = highestCertId;

                        RA::Debug("RA_Enroll_Processor::ProcessRecovery","Calculated new CertID %d.",newCertId);

                        char certId[3];
                        char certAttrId[3];
                        char privateKeyAttrId[3];
                        char publicKeyAttrId[3];
                        int pubKeyNumber=0;
                        int priKeyNumber=0;
                       
                        certId[0] = 'C';
                        certId[1] = '0' + newCertId;
                        certId[2] = 0;

                        certAttrId[0] = 'c';
                        certAttrId[1] = '0' + newCertId;
                        certAttrId[2] = 0;
 
			pubKeyNumber = 2 * newCertId + 1;
			priKeyNumber = 2 * newCertId;

			privateKeyAttrId[0] = 'k';
                        privateKeyAttrId[1] = '0' + priKeyNumber;
                        privateKeyAttrId[2] = 0;

			publicKeyAttrId[0] = 'k';
                        publicKeyAttrId[1] = '0' + pubKeyNumber;
                        publicKeyAttrId[2] = 0;

                        RA::Debug(
                         "RA_Enroll_Processor::ProcessRecovery",
                         "certId %s certAttrId %s privateKeyAttrId %s publicKeyAtrId %s priKeyNum %d pubKeyNum %d",
                          certId,certAttrId,privateKeyAttrId,publicKeyAttrId,priKeyNumber, pubKeyNumber);

            PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label", 
		            OP_PREFIX, tokenType, keyTypeValue);
            RA::Debug(LL_PER_CONNECTION,FN,
		        "label '%s'", configname);
            const char *pattern = RA::GetConfigStore()->GetConfigAsString(configname);
			const char* label = MapPattern(&nv, (char *) pattern);

			BYTE objid[4];

			objid[0] = 0xFF;
			objid[1] = 0x00;
			objid[2] = 0xFF;
			objid[3] = 0xF3;

			char *tmp_c = NULL;
			if (certs[0] != NULL) {
			  tmp_c = NSSBase64_EncodeItem(0, 0, 0, &(certs[0]->derCert));
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after NSSBase64_EncodeItem");
			} else {
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "no cert!!");
                          PR_snprintf(audit_msg, 512, "Key Recovery failed. no cert");
			  goto rloser;
			}

			if ((tmp_c == NULL) || (strcmp(tmp_c,"")==0)) {
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "NSSBase64_EncodeItem failed");
                          PR_snprintf(audit_msg, 512, "Key Recovery failed. NSSBase64_EncodeItem failed");
			  goto rloser;
			}
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "NSSBase64_EncodeItem succeeded");
			attr[0] = PL_strdup(tmp_c);
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "b64 encoded cert =%s",attr[0]);

                         if( newCertId > 9) {

                            RA::Debug(LL_PER_CONNECTION,FN,
                                "RA_Enroll_Processor::ProcessRecovery","Possible misconfiguration or out of sync token!");
                                PR_snprintf(audit_msg, 512,
                                    "Renewal of cert failed, misconfiguration or out of sync token!");
                                goto rloser;
                        }
	
                        // get serverKeygen and archive, check if they are enabled.
                        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.serverKeygen.enable", 
		          OP_PREFIX, tokenType, keyTypeValue);
                        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	                  "looking for config %s", configname);
                        serverKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, 0);
                        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.serverKeygen.archive",
                          OP_PREFIX, tokenType, keyTypeValue);
                        RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	                  "looking for config %s", configname);
                        archive = RA::GetConfigStore()->GetConfigAsBool(configname, 0);
			PR_snprintf((char *)configname, 256, "%s.%s.tks.conn", OP_PREFIX, tokenType);
			connid = RA::GetConfigStore()->GetConfigAsString(configname);
                        tksServerKeygen = false;
                        if (connid != NULL) {
                            PR_snprintf((char *)configname, 256, "conn.%s.serverKeygen", connid);
                            tksServerKeygen = RA::GetConfigStore()->GetConfigAsBool(configname, 0);
                        } else {
			    r = false;
			    o_status = STATUS_ERROR_NO_TKS_CONNID;
                            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::ProcessRecovery", "Missing tks.connid");
                            PR_snprintf(audit_msg, 512, "Key Recovery failed. Missing tks.connid");
			    goto rloser;
                        }
                        
                        if (tksServerKeygen && archive && serverKeygen) {
                            RA::RecoverKey(session, lostTokenCUID, userid, 
				                           channel->getDrmWrappedDESKey(),
				                           attr[0], &o_pub, &o_priv,
				                           (char *)drmconnid,&ivParam);
                        } else {
			    r = false;
			    o_status = STATUS_ERROR_KEY_ARCHIVE_OFF;
                            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::ProcessRecovery", "Archival is turned off");
                            PR_snprintf(audit_msg, 512, "Key Recovery failed. Archival is turned off");
			    goto rloser;
                        }

			if (o_pub == NULL) {
			  RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::DoEnrollment()", "RecoverKey called, o_pub is NULL");
			  r = false;
			  o_status = STATUS_ERROR_RECOVERY_FAILED;
                          PR_snprintf(audit_msg, 512, "Key Recovery failed. o_pub is NULL");
			  goto rloser;
			} else
			  RA::Debug(LL_PER_PDU, "DoEnrollment", "o_pub = %s", o_pub);

                       
			if (o_priv == NULL) {
			  RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::DoEnrollment()", "RecoverKey called, o_priv is NULL");
			  /* XXX
			     r = false;
			     o_status = STATUS_ERROR_RECOVERY_FAILED;
			     goto rloser;
			  */
			} else
			  RA::Debug(LL_PER_PDU, "DoEnrollment", "o_priv not NULL");

                        if (ivParam == NULL) {
                            RA::Debug(LL_PER_CONNECTION,"RA_Enroll_Processor::ProcessRecovery",
                            "ProcessRecovery called, ivParam is NULL");
                             r = false;
                             o_status = STATUS_ERROR_RECOVERY_FAILED;
                             PR_snprintf(audit_msg, 512, "RA_Enroll_Processor::ProcessRecovery called, ivParam is NULL");
                             goto rloser;
                        } else {
                           RA::Debug(LL_PER_CONNECTION,"ProcessRecovery",
                            "ivParam = %s", ivParam);
                        }
                       
			RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::ProcessRecovery()", "key injection for RecoverKey occurs here");
			/*
			 * the following code converts b64-encoded public key info into SECKEYPublicKey
			 */
			SECStatus rv;
			SECItem der;
               
			der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
			rv = ATOB_ConvertAsciiToItem (&der, o_pub);
			if (rv != SECSuccess){
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key, rv is failure");
			  SECITEM_FreeItem(&der, PR_FALSE);
			  r = false;
			  o_status = STATUS_ERROR_RECOVERY_FAILED;
                          PR_snprintf(audit_msg, 512, "Key Recovery failed. after converting public key, rv is failure");
			  goto rloser;
			}else {
			  RA::Debug(LL_PER_PDU, "ProcessRecovery", "item len=%d, item type=%d",der.len, der.type);

			  spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der);

			  if (spki != NULL) {
			    RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key spki is not NULL");
			    pk_p = SECKEY_ExtractPublicKey(spki);
			    if (pk_p != NULL)
			      RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key pk_p is not NULL");
			    else
			      RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key, pk_p is NULL");
			  } else
			    RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key, spki is NULL");

			}
			SECITEM_FreeItem(&der, PR_FALSE);
			SECKEY_DestroySubjectPublicKeyInfo(spki);

			if( pk_p == NULL ) {
			    RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                          "pk_p is NULL; unable to continue");
			    r = false;
			    o_status = STATUS_ERROR_RECOVERY_FAILED;
                            PR_snprintf(audit_msg, 512, "Key Recovery failed. pk_p is NULL; unable to continue");
			    goto rloser;
            }

                        // XXX - Add serial number and public key to audit log 
                        //get serial number for audit log
                        //char msg[2048];
                        //RA::ra_tus_print_integer(msg, &certs[0]->serialNumber);

                        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
                          userid != NULL ? userid : "",
                          cuid != NULL ? cuid : "",
                          msn != NULL ? msn : "",
                          "success",
                          "enrollment",
                          final_applet_version != NULL ? final_applet_version : "",
                          keyVersion != NULL? keyVersion : "",
                          "key recovered successfully");

            if (!isECC) {
                /* fill in keyid, modulus, and exponent */

                si_mod = pk_p->u.rsa.modulus;
                modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);
            }

			spkix = SECKEY_CreateSubjectPublicKeyInfo(pk_p);

			/* 
			 * RFC 3279
			 * The keyIdentifier is composed of the 160-bit SHA-1 hash of the
			 * value of the BIT STRING subjectPublicKey (excluding the tag,
			 * length, and number of unused bits).
			 */
			spkix->subjectPublicKey.len >>= 3;
			si_kid = PK11_MakeIDFromPubKey(&spkix->subjectPublicKey);
			spkix->subjectPublicKey.len <<= 3;
			SECKEY_DestroySubjectPublicKeyInfo(spkix);

			keyid = new Buffer((BYTE*) si_kid->data, si_kid->len);

            if (!isECC) {
                si_exp = pk_p->u.rsa.publicExponent;
                exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);

                RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
                    " keyid, modulus and exponent are retrieved");
            }

                        ktypes[actualCertIndex] = PL_strdup(keyTypeValue);
                        // We now store the token id of the original token
                        // that generates this certificate so we can
                        // tell if the certificate should be operated
                        // on or not during formation operation
                        origins[actualCertIndex] = PL_strdup(lostTokenCUID);
                        certificates[actualCertIndex] = certs[0];


			// Create KeyBlob for private key, but first b64 decode it
			/* url decode o_priv */
			{
			  Buffer priv_keyblob;
			  Buffer *decodeKey = Util::URLDecode(o_priv);
			  //RA::DebugBuffer("cfu debug"," private key =",decodeKey);
			  priv_keyblob =
			    Buffer(1, 0x01) + // encryption
			    Buffer(1, 0x09)+ // keytype is RSAPKCS8Pair
			    Buffer(1,(BYTE)(keysize/256)) + // keysize is two bytes
			    Buffer(1,(BYTE)(keysize%256)) +
			    Buffer((BYTE*) *decodeKey, decodeKey->size());
			  delete decodeKey;

			  //inject PKCS#8 private key
			  BYTE perms[6];

			  perms[0] = 0x40;
			  perms[1] = 0x00;
			  perms[2] = 0x40;
			  perms[3] = 0x00;
			  perms[4] = 0x40;
			  perms[5] = 0x00;

			  if (channel->CreateObject(objid, perms, priv_keyblob.size()) != 1) {
			    r = false;
                            PR_snprintf(audit_msg, 512, "Failed to write key to token. CreateObject failed.");
			    goto rloser;
			  }

			  if (channel->WriteObject(objid, (BYTE*)priv_keyblob, priv_keyblob.size()) != 1) {
			    r = false;
                            PR_snprintf(audit_msg, 512, "Failed to write key to token. WriteObject failed.");
			    goto rloser;
			  }
			}

			/* url decode the wrapped kek session key and keycheck*/
			{
			  Buffer data;
			  /*
			    RA::Debug(LL_PER_PDU, "", "getKekWrappedDESKey() returns =%s", channel->getKekWrappedDESKey());
			    RA::Debug(LL_PER_PDU, "", "getKeycheck() returns =%s", channel->getKeycheck());
			  */
			  Buffer *decodeKey = Util::URLDecode(channel->getKekWrappedDESKey());

			  /*
			    RA::Debug(LL_PER_PDU, "", "des key item len=%d",
			    decodeKey->size());
			    RA::DebugBuffer("cfu debug", "DES key =", decodeKey);
			  */
			  char *keycheck = channel->getKeycheck();
			  Buffer *decodeKeyCheck = Util::URLDecode(keycheck);
			  if (keycheck)
			    PL_strfree(keycheck);

			  /*
			    RA::Debug(LL_PER_PDU, "", "keycheck item len=%d",
			    decodeKeyCheck->size());
			    RA::DebugBuffer("cfu debug", "key check=", decodeKeyCheck);
			  */

                          BYTE alg = 0x80;
                          if(decodeKey && decodeKey->size()) {
                              alg = 0x81;
                          }

                          //Get iv data returned by DRM

                          Buffer *iv_decoded = Util::URLDecode(ivParam);
                          if (ivParam) {
                             PL_strfree(ivParam);
                          }

                          if(iv_decoded == NULL) {
                             r = false;
                             PR_snprintf(audit_msg, 512, "ProcessRecovery: store keys in token failed, iv data not found");
                             delete decodeKey;
                             delete decodeKeyCheck;
                             goto rloser;
                          }

			  data =
			    Buffer((BYTE*)objid, 4)+ // object id
                            Buffer(1,alg) +
			    //Buffer(1, 0x08) + // key type is DES3: 8
			    Buffer(1, (BYTE) decodeKey->size()) + // 1 byte length
			    Buffer((BYTE *) *decodeKey, decodeKey->size())+ // key -encrypted to 3des block
			    // check size
			    // key check
			    Buffer(1, (BYTE) decodeKeyCheck->size()) + //keycheck size
			    Buffer((BYTE *) *decodeKeyCheck , decodeKeyCheck->size())+ // keycheck
                            Buffer(1, iv_decoded->size())+ // IV_Length
                            Buffer((BYTE*)*iv_decoded, iv_decoded->size());

			    //RA::DebugBuffer("cfu debug", "ImportKeyEnc data buffer =", &data);

			  delete decodeKey;
			  delete decodeKeyCheck;
                          delete iv_decoded;

			  if (channel->ImportKeyEnc((keyUser << 4)+priKeyNumber,
						    (keyUsage << 4)+pubKeyNumber, &data) != 1) {
			    r = false;
                            PR_snprintf(audit_msg, 512, "Failed to write key to token. ImportKeyEnc failed.");
			    goto rloser;
			  }
			}

			{
			  Buffer *certbuf = new Buffer(certs[0]->derCert.data, certs[0]->derCert.len);
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (certId[0] << 24) +
							   (certId[1] << 16),
							   certbuf);
			  pkcs11objx->AddObjectSpec(objSpec);
			}
			{
              Buffer b = channel->CreatePKCS11CertAttrsBuffer(
                  KEY_TYPE_ENCRYPTION , certAttrId, label, keyid);
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (certAttrId[0] << 24) +
							   (certAttrId[1] << 16),
							   &b);
			  pkcs11objx->AddObjectSpec(objSpec);
			}

			{
              Buffer b;
              if (!isECC) {
                  b = channel->CreatePKCS11PriKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
                      privateKeyAttrId, label, keyid, modulus, OP_PREFIX, 
                      tokenType, keyTypePrefix);
              } else { //isECC
                  eccParams  =   &pk_p->u.ec.DEREncodedParams;
                  b = channel->CreatePKCS11ECCPriKeyAttrsBuffer(KEY_TYPE_ENCRYPTION,
                      privateKeyAttrId, label, keyid, eccParams, OP_PREFIX,
                      tokenType, keyTypePrefix);
              }

			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (privateKeyAttrId[0] << 24) +
							   (privateKeyAttrId[1] << 16),
							   &b);
			  pkcs11objx->AddObjectSpec(objSpec);
			}

			{
              Buffer b;
              if (!isECC) {
                  b = channel->CreatePKCS11PubKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
                  publicKeyAttrId, label, keyid, 
                  exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
             } else {
                 b = channel->CreatePKCS11ECCPubKeyAttrsBuffer(KEY_TYPE_ENCRYPTION,
                        publicKeyAttrId, label, keyid,&pk_p->u.ec, eccParams,
                        OP_PREFIX, tokenType, keyTypePrefix);
             }

			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (publicKeyAttrId[0] << 24) +
							   (publicKeyAttrId[1] << 16),
							   &b);
			  pkcs11objx->AddObjectSpec(objSpec);
			}

                        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
                          userid != NULL ? userid : "",
                          cuid != NULL ? cuid : "",
                          msn != NULL ? msn : "",
                          "success",
                          "enrollment",
                          final_applet_version != NULL ? final_applet_version : "",
                          keyVersion != NULL? keyVersion : "",
                          "key written to token successfully");

		    rloser:

			if( modulus != NULL ) {
			  delete modulus;
			  modulus = NULL;
			}
			if( keyid != NULL ) {
			  delete keyid;
			  keyid = NULL;
			}
			if( exponent != NULL ) {
			  delete exponent;
			  exponent = NULL;
			}
			if( attr[0] != NULL ) {
			  PR_Free(attr[0]);
			  attr[0] = NULL;
			}
			if( o_pub != NULL ) {
			  PR_Free(o_pub);
			  o_pub = NULL;
			}

			if (o_priv !=NULL) {
			  PR_Free(o_priv);
			  o_priv = NULL;
			}

			if( si_kid != NULL ) {
			  SECITEM_FreeItem( si_kid, PR_TRUE );
			  si_kid = NULL;
			}
			if( label != NULL ) {
			  PL_strfree( (char *) label );
			  label = NULL;
			}

                    }
                }
            } else {
	      r = false;
	      o_status = STATUS_ERROR_LDAP_CONN;
	      goto loser;
            }
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
		      "Filter to find certificates = %s", filter);
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
		      "Recover key for %s", keyTypeValue);

           //Unrevoke this successfully recovered certificate
           if ( o_status == STATUS_ERROR_RECOVERY_IS_PROCESSED && e != NULL) {
               char *statusString = NULL;
               int statusNum = UnrevokeRecoveredCert(e, statusString);

               // Error from the CA log and get out
               if (statusNum != 0) {
                       r = false;
                       o_status =  STATUS_ERROR_RECOVERY_FAILED;
                       if (statusString == NULL || strlen(statusString) == 0) {
                           statusString = PL_strdup("Unknown Key Recovery Error.");
                       }
                       RA::Debug("RA_Enroll::Prcessor::ProcessRecovery", "Unrevoke statusString: %s",statusString);
                       PR_snprintf(audit_msg, 512, "Key Recovery failed. Can not unrevoke recovered certificate! %s",statusString);
                       if (statusString) {
                           PL_strfree(statusString);
                       }
                       goto loser;
                }

                if (statusString) {
                   PL_strfree(statusString);
                } 
           }  
        }
        if( !legalScheme)  {
	      RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
		    "Misconfigure parameter for %s", configname);
	      r = false;
	      o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
	      goto loser;
        }

        actualCertIndex++;
         RA::Debug("RA_Enroll_Processor::ProcessRecovery","leaving cert loop... ");
    }

 loser:
    if (strlen(audit_msg) > 0) { // a failure occurred
        RA::Audit(EV_ENROLLMENT, AUDIT_MSG_PROC,
          userid != NULL ? userid : "",
          cuid != NULL ? cuid : "",
          msn != NULL ? msn : "",
          "failure",
          "enrollment",
          final_applet_version != NULL ? final_applet_version : "",
          keyVersion != NULL? keyVersion : "",
          audit_msg);
    }

    if( pretty_cuid != NULL ) {
        PR_Free( (char *) pretty_cuid );
        pretty_cuid = NULL;
    }
    if( result != NULL ) {
        ldap_msgfree( result );
    }
    if (pk_p != NULL) {
            RA::Debug(LL_PER_CONNECTION,FN,"ProcessRecovery  about to call SECKEY_DestroyPublicKey on pk_p");
            SECKEY_DestroyPublicKey(pk_p);
    }

     RA::Debug("RA_Enroll_Processor::ProcessRecovery","leaving whole function...");
    return r;
}

int RA_Enroll_Processor::DoPublish(const char *cuid,SECItem *encodedPublicKeyInfo,Buffer *cert,const char *publisher_id,char *applet_version)
{

        int res = 0;

        CERTCertificate *certObj = NULL;
		const char *FN="DoPublish";

        unsigned char *public_key_data = NULL;
        int public_key_len = 0;
        PRTime not_before,not_after;

        // 1980 epoch offset

        PRTime ul_1980 = ((365 * 10 + 2) * 86400);


        if(! encodedPublicKeyInfo)
        {
            return 0;
        }


        RA::Debug(LL_PER_CONNECTION,FN, "1980 epoch offset %u ",ul_1980);

        PRUint32  ul_not_before, ul_not_after;

        int key_type =  1;    

        RA::Debug(LL_PER_CONNECTION,FN, "We got a public key back. Now attempt publish operation.");

        public_key_data = encodedPublicKeyInfo->data;
        public_key_len = encodedPublicKeyInfo->len;

        unsigned long applet_version_long =  0;

        char *end = NULL;

        if(applet_version)
        {
            applet_version_long = (unsigned long) strtol((const char *)applet_version,&end,16);
        }
        if(cuid)
        {
            RA::Debug(LL_PER_CONNECTION,FN,
				"cuid %s public_key_len %ud",cuid,public_key_len);

        }
        if(cert)
        {
            RA::Debug(LL_PER_CONNECTION,FN,
				"cert.size() %ld. cert %s",cert->size(),(char *) (BYTE *) cert);

            certObj = CERT_DecodeCertFromPackage((char *) cert->string(), (int) cert->size());
        }
        RA::Debug(LL_PER_CONNECTION,FN,
				"certObj %p.",certObj);

        if(certObj && cuid != NULL)
        {
             RA::Debug(LL_PER_CONNECTION,FN,
				 "We got pointer to Certificate data.");
             CERT_GetCertTimes (certObj, &not_before, &not_after);

             ul_not_before = ( PRUint32 )( not_before/1000000 );
             ul_not_after = ( PRUint32 )( not_after/1000000 );

             RA::Debug(LL_PER_CONNECTION,FN,
				"Cert date not_before %u not_after %u.",ul_not_before,ul_not_after);

              // Convert to 1980 epoch time

              ul_not_before -= (PRUint32) ul_1980;
              ul_not_after  -= (PRUint32) ul_1980;


              RA::Debug(LL_PER_CONNECTION,FN,
					"Cert date, after 1980 translation, not_before %ul not_after %ul.",ul_not_before,ul_not_after);


              PublisherEntry *publish = RA::getPublisherById(publisher_id);

              if(publish != NULL)
              {
                  RA::Debug(LL_PER_CONNECTION,FN,
						"publisher %s ",publish->id);
              }
              else
              {
                   RA::Debug(LL_PER_CONNECTION,FN,
						"publisher %s not found ",publisher_id);

              }

              res = 0;
              if(publish && publish->publisher  )
              {
                  IPublisher *pb = publish->publisher;
                  RA::Debug(LL_PER_CONNECTION,FN,
					"publisher %p ",pb);
                  res = pb->publish((unsigned char *) cuid,(int) strlen(cuid),(long) key_type,(unsigned char *) public_key_data,(int) public_key_len,(unsigned long)ul_not_before,(unsigned long) ul_not_after,applet_version_long,applet_version_long - ul_1980);

              }
              if(!res)
              {
                   RA::Debug(LL_PER_CONNECTION,FN,
						"Publish failed.");
              }
              else
              {
                    RA::Debug(LL_PER_CONNECTION,FN,
						"Publish success.");
              }
        }
        else
        {
            RA::Debug(LL_PER_CONNECTION,FN,
					"No Publish failed Either cuid or certObj is NULL.");
        }

        if(certObj)
        {

            CERT_DestroyCertificate(certObj);
        }
        return res;
}

int RA_Enroll_Processor::GetNextFreeCertIdNumber(PKCS11Obj *pkcs11objx)
{
    if(!pkcs11objx)
        return 0;

    //Look through the objects actually currently on the token
    //to determine an appropriate free certificate id

     int num_objs = pkcs11objx->PKCS11Obj::GetObjectSpecCount();
    char objid[2];

    int highest_cert_id = 0;
    for (int i = 0; i< num_objs; i++) {
        ObjectSpec* os = pkcs11objx->GetObjectSpec(i);
        unsigned long oid = os->GetObjectID();
        objid[0] = (char)((oid >> 24) & 0xff);
        objid[1] = (char)((oid >> 16) & 0xff);

        if(objid[0] == 'C') { //found a certificate

            int id_int = objid[1] - '0';

            if(id_int > highest_cert_id) {
                highest_cert_id = id_int;
            }
          }
    }

    RA::Debug(LL_PER_CONNECTION,
                                  "RA_Enroll_Processor::GetNextFreeCertIdNumber",
                                   "returning id number: %d", highest_cert_id + 1);
    return highest_cert_id + 1;
}

//Unrevoke a cert that has been recovered
int RA_Enroll_Processor::UnrevokeRecoveredCert(LDAPMessage *e, char *&statusString)
{
    char configname[256];
    CertEnroll certEnroll;
    //Default to error return
    int statusNum = 0;
    char serial[100]="";
    CERTCertificate **attr_certificate = NULL;

    RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                      "About to unrevoke recovered certificate.");

    if (e == NULL) {
        return 1;
    }

    char *attr_serial= RA::ra_get_cert_serial( (LDAPMessage *) e );
    char *attr_tokenType = RA::ra_get_cert_tokenType( (LDAPMessage *) e );
    char *attr_keyType = RA::ra_get_cert_type( (LDAPMessage *) e );

    // does the config say we have to revoke this cert?
    PR_snprintf( ( char * ) configname, 256,
                  "op.enroll.%s.keyGen.%s.recovery."
                  "onHold.revokeCert",
                  attr_tokenType, attr_keyType );

    RA::Debug("RA_Enroll_Processor::UnrevokeRecoveredCert",
        "Recovered Cert Unrevoke config value %s \n", configname);
    bool revokeCert = RA::GetConfigStore()->
        GetConfigAsBool( configname, false );
    if( revokeCert ) {
        // Assume the worst
        statusNum = 1;
        // Get the conn to the CA
        PR_snprintf( ( char * ) configname, 256,
                     "op.enroll.%s.keyGen.%s.ca.conn",
                     attr_tokenType, attr_keyType );

        char *connid = ( char * )
             RA::GetConfigStore()->
                 GetConfigAsString( configname );

        if (connid) {
            PR_snprintf( serial, 100, "0x%s", attr_serial );

            attr_certificate= RA::ra_get_certificates(e);
            //Actually make call to the CA to unrevoke
            statusNum = certEnroll.RevokeCertificate(
                false,
                attr_certificate[0], "", serial, connid, statusString);

            RA::Debug("RA_Enroll_Processor::UnrevokeRecoveredCert",
               "Recovered Cert statusNum %d statusString %s \n", statusNum, statusString);
       } 
    }

    if (attr_certificate[0] != NULL)
        CERT_DestroyCertificate(attr_certificate[0]);

    if (attr_serial) {
        PL_strfree(attr_serial);
    }

    if (attr_tokenType) {
        PL_strfree(attr_tokenType);
    }

    if (attr_keyType) {
        PL_strfree(attr_keyType);
    }
    return statusNum;
}

void PrintPRTime(PRTime theTime, const char *theName)
{
  struct tm t;
  PRExplodedTime explode;
  char buffer[256];

  if(!theName)
      return;
  
  PR_ExplodeTime (theTime, PR_LocalTimeParameters, &explode);
  
  t.tm_sec = explode.tm_sec;
  t.tm_min = explode.tm_min;
  t.tm_hour = explode.tm_hour;
  t.tm_mday = explode.tm_mday;
  t.tm_mon = explode.tm_month;
  t.tm_year = explode.tm_year - 1900;
  t.tm_wday = explode.tm_wday;
  t.tm_yday = explode.tm_yday;
  
  PL_strncpy(buffer, asctime (&t), 256);
  buffer[256 - 1] = 0;
 
  RA::Debug("PrintPRTime","Date/Time: %s %s",theName,buffer); 
}
