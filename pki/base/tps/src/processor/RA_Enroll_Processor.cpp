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
		BYTE se_p1, BYTE se_p2, int keysize, const char *connid, const char *keyTypePrefix,char * applet_version)
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

    float progress_block_size = (float) (end_progress - start_progress) / keyTypeNum;
    RA::Debug(LL_PER_CONNECTION,FN,
	            "Start of keygen/certificate enrollment");

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

    if (key_type == KEY_TYPE_ENCRYPTION) {// do serverSide keygen?
                                                                                
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
                           archive, keysize);

      if (pKey == NULL) {
	    RA::Error(LL_PER_CONNECTION,FN,
		"Failed to generate key on server. Please check DRM.");
	RA::Debug(LL_PER_CONNECTION,FN,
		"ServerSideKeyGen called, pKey is NULL");
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
	goto loser;
      } else
	RA::Debug(LL_PER_CONNECTION,FN,
		"key value = %s", pKey);


      if (wrappedPrivKey == NULL) {
	RA::Debug(LL_PER_CONNECTION,FN,
		"ServerSideKeyGen called, wrappedPrivKey is NULL");
	status = STATUS_ERROR_MAC_ENROLL_PDU;
	goto loser;
      } else
	RA::Debug(LL_PER_CONNECTION,FN,
		"wrappedPrivKey = %s", wrappedPrivKey);

      if (ivParam == NULL) {
	RA::Debug(LL_PER_CONNECTION,FN,
		"ServerSideKeyGen called, ivParam is NULL");
	status = STATUS_ERROR_MAC_ENROLL_PDU;
	goto loser;
      } else
	RA::Debug(LL_PER_CONNECTION,FN,
		"ivParam = %s", ivParam);

      /*
       * the following code converts b64-encoded public key info into SECKEYPublicKey
       */
      SECStatus rv;
      SECItem der;
      CERTSubjectPublicKeyInfo* spki = NULL;
               
      der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
      rv = ATOB_ConvertAsciiToItem (&der, pKey);
      if (rv != SECSuccess){
	RA::Debug(LL_PER_CONNECTION,FN,
		"failed to convert b64 private key to binary");
	SECITEM_FreeItem(&der, PR_FALSE);
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
	goto loser;
      }else {
	RA::Debug(LL_PER_CONNECTION,FN,
		"decoded private key as: secitem (len=%d)",der.len);

	spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der);

	if (spki != NULL) {
	  RA::Debug(LL_PER_CONNECTION,FN,
		"Successfully decoded DER SubjectPublicKeyInfo structure");
	  pk_p = SECKEY_ExtractPublicKey(spki);
	  if (pk_p != NULL)
	    RA::Debug(LL_PER_CONNECTION,FN,
		"Successfully extracted public key from SPKI structure");
	  else
	    RA::Debug(LL_PER_CONNECTION,FN,
		"Failed to extract public key from SPKI");
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


      // send status update to the client
	StatusUpdate(session, extensions,
			start_progress + (index * progress_block_size) + 
			(progress_block_size * 55/100) /* progress */, 
			"PROGRESS_PARSE_PUBLIC_KEY");

      RA::Debug(LL_PER_CONNECTION,FN,
		"About to Parse Public Key");

      pk_p = certEnroll->ParsePublicKeyBlob(
                (unsigned char *)(BYTE *)*public_key /*blob*/, 
                plaintext_challenge);

      if (pk_p == NULL) {
	    RA::Error(LL_PER_CONNECTION,FN,
		  "Failed to parse public key");
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        goto loser;
      }

    } //serverKeygen or not

    RA::Debug(LL_PER_CONNECTION,FN,
		"Keys generated. Proceeding with certificate enrollment");

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
		    connid, ppEncodedPublicKeyInfo);

    if (cert == NULL) {
        status = STATUS_ERROR_MAC_ENROLL_PDU;
        goto loser;
    }

    /* fill in keyid, modulus, and exponent */

    si_mod = pk_p->u.rsa.modulus;
    modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);

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
    si_exp = pk_p->u.rsa.publicExponent;
    exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);

    RA::Debug(LL_PER_CONNECTION,FN,
	      "Keyid, modulus and exponent have been extracted from public key");

    SECKEY_DestroySubjectPublicKeyInfo(spkix);

    cert_string = (char *) cert->string();
    certificates[index] = CERT_DecodeCertFromPackage((char *) cert_string, 
      (int) cert->size());
    if (certificates[index] != NULL) {
        char msg[2048];
        RA::ra_tus_print_integer(msg, &certificates[index]->serialNumber);
        RA::Debug("DoEnrollment", "Received Certificate");
        RA::Debug("DoEnrollment", msg);
    }
    free(cert_string);
    ktypes[index] = strdup(keyType);
    origins[index] = strdup(cuid);

    if (serverKeygen) {
      //do PKCS#8

      BYTE objid[4];

      objid[0] = 0xFF;
      objid[1] = 0x00;
      objid[2] = 0xFF;
      objid[3] = 0xF3;
      Buffer priv_keyblob;
      /* url decode wrappedPrivKey */
      {
	Buffer *decodeKey = Util::URLDecode(wrappedPrivKey);
	// RA::DebugBuffer("cfu debug"," private key =",decodeKey);
	priv_keyblob =
	  Buffer(1, 0x01) + // encryption
	  Buffer(1, 0x09)+ // keytype is RSAPKCS8Pair
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
	goto loser;
      }


      if (channel->WriteObject(objid, (BYTE*)priv_keyblob, priv_keyblob.size()) != 1) {
	status = STATUS_ERROR_MAC_ENROLL_PDU;
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

        BYTE alg = 0x80;
        if(decodeKey && decodeKey->size()) {
            alg = 0x81;
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
	  Buffer((BYTE*)*iv_decoded, iv_decoded->size());

	delete iv_decoded;
	//      RA::DebugBuffer("cfu debug", "ImportKeyEnc data buffer =", &data);

	delete decodeKey;
	delete decodeKeyCheck;
      }

      if (channel->ImportKeyEnc(se_p1, se_p2, &data) != 1) {
	status = STATUS_ERROR_MAC_ENROLL_PDU;
	goto loser;
      }

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
        goto loser;
      }

    if (cert != NULL) {
      RA::Debug(LL_PER_CONNECTION,FN,
		"Enroll Certificate Finished");
    } else {
      RA::Error(LL_PER_CONNECTION,FN,
	"Enroll Certificate Failure");

        status = STATUS_ERROR_MAC_ENROLL_PDU;
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
        	goto loser;
    	}
    }

    if (pkcs11obj_enable) {
    	RA::Debug(LL_PER_CONNECTION,FN,
		"Create PKCS11 Private Key Attributes Buffer");
    	Buffer b = channel->CreatePKCS11PriKeyAttrsBuffer(key_type, 
			pri_attr_id, label, keyid, modulus, OP_PREFIX, 
			tokenType, keyTypePrefix);
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
        	goto loser;
    	}
    }

    if (pkcs11obj_enable) {
    	Buffer b = channel->CreatePKCS11PubKeyAttrsBuffer(key_type, 
			pub_attr_id, label, keyid, 
           exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
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
        	goto loser;
    	}
    }
    RA::Debug(LL_PER_CONNECTION,FN, "End of keygen/certificate enrollment");

loser:
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
      delete token_status;
    }
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
	      "Major=%d Minor=%d Applet Major=%d Applet Minor=%d", 
			o_major_version, o_minor_version, o_app_major_version, o_app_minor_version);
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
		RA_Status &o_status )
{
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
		if (g_applet_target_version == NULL) {
			g_applet_target_version = RA::GetConfigStore()->GetConfigAsString(configname);
		}
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
			if (applet_dir == NULL) {
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

			if (UpgradeApplet(a_session, OP_PREFIX, (char*) a_tokenType,
				o_major_version, o_minor_version, 
				g_applet_target_version, 
				applet_dir, security_level, 
				connid, a_extensions, 
				5, 
				12) != 1) {

				RA::Debug(FN, "applet upgrade failed");
				/**
				 * Bugscape #55709: Re-select Net Key Applet ONLY on failure.
				 */
				SelectApplet(a_session, 0x04, 0x00, a_aid);
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "applet upgrade error", "", a_tokenType);
				o_status = STATUS_ERROR_UPGRADE_APPLET;		 
				r = false;
				goto loser;
			} else {
				// there may be a better place to do this, but worth testing here
				// RA::tdb_update(a_cuid, g_applet_target_version);
			}

			// Upgrade Applet reported success
			RA::Audit("Enrollment", "op='applet_upgrade' app_ver='%s' new_app_ver='%s'",
					o_current_applet_on_token, g_applet_target_version);
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
            	RA::Audit("Enrollment", "status='error' key_ver=00 cuid='%s' msn='%s' note='failed to create secure channel'", a_cuid, a_msn );
				RA::Error(FN, "failed to establish secure channel");
				o_status = STATUS_ERROR_SECURE_CHANNEL;		 
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "secure channel error", "", a_tokenType);
				goto loser;
			}

			/* Complete the secure channel handshake */
			/* XXX need real enumeration of error codes here */
			rc = o_channel->ExternalAuthenticate();
			if (rc != 1) {
				RA::Error(FN, "External authentication in secure channel failed");
				o_status = STATUS_ERROR_EXTERNAL_AUTH;
				/* XXX should print out error codes */
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "external authentication error", "", a_tokenType);
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
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "create card key error", "", a_tokenType);
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
			RA::Audit("Enrollment", "op='key_change_over' cuid='%s' msn='%s' old_key_ver='%02x' new_key_ver='%02x'",  a_cuid, a_msn, curVersion, ((BYTE*)newVersion)[0]);

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
				RA::tdb_activity(a_session->GetRemoteIP(), a_cuid, "enrollment", "failure", "secure channel setup error", "", a_tokenType);
				goto loser;
			} else {
				RA::Debug(FN, "Key Upgrade has completed successfully.");
				r = true;  // Success!!
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
	}
loser:
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

    const char *keyVersion = PL_strdup( "" );
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
	RA_Status st;
    int token_present = 0;
    bool renewed = false;

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

    if (RA::ra_is_token_present(cuid)) {
        RA::Debug(FN, "Found token %s", cuid);
        if (RA::ra_is_tus_db_entry_disabled(cuid)) {
            RA::Error(FN, "CUID %s Disabled", cuid);
            status = STATUS_ERROR_DISABLED_TOKEN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "token disabled", "", tokenType);
            goto loser;
        }

        if (!RA::ra_allow_token_reenroll(cuid) &&
            !RA::ra_allow_token_renew(cuid)) {
            RA::Error(FN, "CUID %s Re-Enrolled Disallowed", cuid);
            status = STATUS_ERROR_DISABLED_TOKEN;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "token re-enrollment or renewal disallowed", "", tokenType);
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
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "unknown token disallowed", "", tokenType);
            goto loser;
        }
    }

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
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "token type not found", "", tokenType);
        goto loser;
    }

	/* figure some more information about the applet version */
	/* XXX should probably move this further down, since the results
       of this function aren't used til much later */
	if (!FormatAppletVersionInfo(session, tokenType, cuid,
		app_major_version, app_minor_version,
		status,
		final_applet_version /*out */)) goto loser;

	PR_snprintf((char *)configname, 256, "%s.%s.loginRequest.enable", OP_PREFIX, tokenType);
	if (!RequestUserId(session, extensions, configname, tokenType, cuid, login, userid, status)){
		goto loser;
	}
    
    PR_snprintf((char *)configname, 256, "%s.%s.auth.enable", OP_PREFIX, tokenType);

	if (!AuthenticateUser(session, configname, cuid, extensions, 
				tokenType, login, userid, status)){
		goto loser;
	}
        
	StatusUpdate(session, extensions, 4, "PROGRESS_APPLET_UPGRADE");

	if (! CheckAndUpgradeApplet(
		session,
		extensions,
		cuid,
		tokenType,
		final_applet_version,
		app_major_version, app_minor_version,
		//appletVersion,
		NetKeyAID,
		status )) {
		goto loser;
	}
	

    isPinPresent = IsPinPresent(session, 0x0);

	StatusUpdate(session, extensions, 12, "PROGRESS_KEY_UPGRADE");

	if (!CheckAndUpgradeSymKeys(
		session,
		extensions,
		cuid,
		tokenType,
		msn,
		CardManagerAID,
		NetKeyAID,
		channel,
		status)) 
	{
		goto loser;
	}
		

    /* we should have a good channel here */
    if (channel == NULL) {
            RA::Error(FN, "no good channel");
            status = STATUS_ERROR_CREATE_CARDMGR;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "secure channel setup error", "",tokenType);
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
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "external authentication error", "", tokenType);
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
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "new pin request error", "", tokenType);
        goto loser;
      }
      RA::Debug(LL_PER_CONNECTION, "RA_Enroll_Processor::Process",
	      "after RequestNewPin, succeeded");

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
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "create pin request error", "", tokenType);
            goto loser;
        }
      }
    }

      rc = channel->ResetPin(0x0, new_pin);
      if (rc == -1) {
	  RA::Error("RA_Enroll_Processor::Process",
		  "reset pin failed");

          status = STATUS_ERROR_MAC_RESET_PIN_PDU;
            RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "reset pin request error", "", tokenType);
          goto loser;
      }
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
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "challenge encryption error", "", tokenType);
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
          goto loser;
        }

		if (((unsigned char *)objectID)[0] == 'z' && 
				((unsigned char *)objectID)[1] == '0') {
			lastFormatVersion = (((BYTE*)*o)[0] << 8) + 
					(((BYTE*)*o)[1]);
			lastObjectVersion = (((BYTE*)*o)[2] << 8) + 
					(((BYTE*)*o)[3]);
      			foundLastObjectVersion = 1;

			//
			delete pkcs11objx;
			pkcs11objx = PKCS11Obj::Parse(o, 0);
			seq = 0;
		} else {
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
                RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertificates"," returns false");
                goto loser;
            } else {
                RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertificates"," returns true");
            }
        } else {
            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process - after GenerateCertsAfterRecoveryPolicy", "status is %d", STATUS_NO_ERROR);
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

      RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", 
              "about to write certificate chain");

      /* add additional certificate objects */
      PR_snprintf((char *)configname, 256, "%s.certificates.num", 
		    OP_PREFIX);
      int certNum = RA::GetConfigStore()->GetConfigAsInt(configname);
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

	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

	if (channel->CreateObject(objid, perms, xb.size()) != 1) {
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
	  goto loser;
	}
      //      channel->CreateObject(objid, xb.size());
	if (channel->WriteObject(objid, (BYTE*)xb, xb.size()) != 1) {
	  status = STATUS_ERROR_MAC_ENROLL_PDU;
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
        }
    }

    /* write lifecycle bit */
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "Set Lifecycle State");
    rc = channel->SetLifecycleState(0x0f);
    if (rc == -1) {
        RA::Error("RA_Enroll_Processor::Process",
		"Set life cycle state failed");
        status = STATUS_ERROR_MAC_LIFESTYLE_PDU;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "set life cycle state error", "", tokenType);
        goto loser;
    }

    rc = channel->Close();
    if (rc == -1) {
        RA::Error("RA_Enroll_Processor::Process",
		"Failed to close channel");
        status = STATUS_ERROR_CONNECTION;
        RA::tdb_activity(session->GetRemoteIP(), cuid, "enrollment", "failure", "channel not closed", "", tokenType);
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
    if (authid == NULL) {
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "authid == NULL");
        RA::Audit("Enrollment", "status='success' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' uid='%s' time='%d msec'",
          final_applet_version, keyVersion, cuid, msn, userid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));
    } else { 
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "has authid");
        RA::Audit("Enrollment", "status='success' app_ver='%s' key_ver='%s' cuid='%s' msn='%s' uid='%s' auth='%s' time='%d msec'",
          final_applet_version, keyVersion, cuid, msn, userid, authid, ((PR_IntervalToMilliseconds(end) - PR_IntervalToMilliseconds(start))));
    }

    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after audit");
loser:
    if (tokenTypes != NULL) {
//cfu hack
if ((o_certNums >1) && renewed){
  o_certNums = 1;
}
        for (int nn=0; nn<o_certNums; nn++) {
            if (tokenTypes[nn] != NULL)
                PL_strfree(tokenTypes[nn]);
            tokenTypes[nn] = NULL;
        }
        free(tokenTypes);
    }

    if( certEnroll != NULL ) {
        delete certEnroll;
        certEnroll = NULL;
    }

    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "before CERT_DestroyCertificate");
    if (certificates != NULL) {
	   for (int i=0;i < o_certNums; i++) {
 			if (certificates[i] != NULL) {
				CERT_DestroyCertificate(certificates[i]);
			}
	   }
       free(certificates);
    }
    RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process", "after CERT_DestroyCertificate");
    if (ktypes != NULL) {
       free(ktypes);
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
    /*
    if( final_applet_version != NULL ) {
        PR_Free( (char *) final_applet_version );
        final_applet_version = NULL;
    }
    */
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
      if (renewed) {
      } else {
        PR_Free(tokentype);
      }
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

    bool r=true;
    int keyTypeNum = 0;
    int i = 0;
    char configname[256];
	const char *FN = "RA_Enroll_Processor::GenerateCertificates";


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
    
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * keyTypeNum);
    o_certNums = keyTypeNum;
    for (i=0; i<keyTypeNum; i++) {
		certificates[i] = NULL;
	}
    ktypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    origins = (char **) malloc (sizeof(char *) * keyTypeNum);
    tokenTypes = (char **) malloc (sizeof(char *) * keyTypeNum);

    for (i=0; i<keyTypeNum; i++) {

        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.keyType.value.%d", OP_PREFIX, tokenType, i);
        const char *keyTypeValue = RA::GetConfigStore()->GetConfigAsString(configname, "signing");

        r = GenerateCertificate(login,keyTypeNum, keyTypeValue, i, session, origins, ktypes, tokenType,
          pkcs11objx, pkcs11obj_enable, extensions, channel, wrapped_challenge,
          key_check, plaintext_challenge, cuid, msn, final_applet_version,
          khex, userid, o_status, certificates);

        tokenTypes[i] = PL_strdup(tokenType);
    }

 loser:
    return r;
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
          (keyUsage << 4)+pubKeyNumber, keySize, caconnid, keyTypePrefix,(char *)final_applet_version);

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
            char ** attr_values = RA::ra_get_attribute_values(e, "tokenStatus");
            RA::Debug(LL_PER_CONNECTION,FN, "tokenStatus = %s",
              attr_values[0]);

            strcpy(tokenStatus, attr_values[0]);
            // free attr_values
            if (attr_values != NULL) {
              int cc = 0;
              while (attr_values[cc] != NULL) {
                free(attr_values[cc]);
                cc++;
              }
              free(attr_values); 
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
                        }
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
 *   for now, just check if it expired
 */
bool isCertRenewable(CERTCertificate *cert){
    PRTime timeBefore, timeAfter, now;
    PRExplodedTime beforePrintable, afterPrintable;
    char *beforestr, *afterstr;

    DER_DecodeTimeChoice(&timeBefore, &cert->validity.notBefore);
    DER_DecodeTimeChoice(&timeAfter, &cert->validity.notAfter);
    now = PR_Now();
    if (timeAfter <= now) {
        return true;
    }
    return false;
/*
    PR_ExplodeTime(timeBefore, PR_GMTParameters, &beforePrintable);
    PR_ExplodeTime(timeAfter, PR_GMTParameters, &afterPrintable);
*/
}

/*
 * cfu
 * DoRenewal - use i_cert's serial number for renewal
 * i_cert - cert to renew
 * o_cert - cert newly issued
 */
bool RA_Enroll_Processor::DoRenewal(const char *connid, const char *profileId, CERTCertificate *i_cert,
CERTCertificate **o_cert)
{
    RA_Status status = STATUS_NO_ERROR;
    bool r = true;
    CertEnroll *certRenewal = NULL;
    Buffer *cert = NULL;
    char *cert_string = NULL;

    const char *FN="RA_Enroll_Processor::DoRenewal";
    PRUint64 snum = DER_GetInteger(&(i_cert)->serialNumber);
    RA::Debug("RA_Enroll_Processor::DoRenewal", "begins renewal for serial number %u with profileId=%s", (int)snum, profileId);

    certRenewal = new CertEnroll();
    cert = certRenewal->RenewCertificate(snum, connid, profileId);
    if (cert == NULL) {
//        status = STATUS_ERROR_MAC_ENROLL_PDU;
        r = false;
        RA::Debug("RA_Enroll_Processor::DoRenewal", "Renewal failed for serial number %d", snum);
        goto loser;
    }
    RA::Debug("RA_Enroll_Processor::DoRenewal", "Renewal suceeded for serial number %d", snum);

    cert_string = (char *) cert->string();
    *o_cert = CERT_DecodeCertFromPackage((char *) cert_string, 
//    o_cert = CERT_DecodeCertFromPackage((char *) cert_string, 
      (int) cert->size());
    if (o_cert != NULL) {
        char msg[2048];
        RA::ra_tus_print_integer(msg, &(o_cert[0])->serialNumber);
//        RA::ra_tus_print_integer(msg, &(o_cert->serialNumber));
        RA::Debug("DoRenewal", "Received newly issued Certificate");
        RA::Debug("DoRenewal", msg);
        RA::Debug("DoRenewal", "yes");
    } else {
        r = false;
    }
    free(cert_string);

loser:
    return r;
}

// cfu
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

    int i = 0;
    const char *FN="RA_Enroll_Processor::ProcessRenewal";

    // e.g. op.enroll.userKey.renewal.keyType.num
    // reneal params will just have to match that of the previous
    // enrollment tps profile. Will try to be smarter later...
    PR_snprintf(configname, 256, "op.enroll.%s.renewal.keyType.num",
      tokenType);
    int keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname, -1);
    if (keyTypeNum == -1) {
        RA::Debug("RA_Enroll_Processor::ProcessRenewal", "Missing the configuration parameter for %s", configname);
        r = false;
        o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        goto loser;
    }

    RA::Debug("RA_Enroll_Processor::ProcessRenewal", "keyType.num=%d", keyTypeNum);

    o_certNums = keyTypeNum;
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * keyTypeNum);
    ktypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    origins = (char **) malloc (sizeof(char *) * keyTypeNum);
    tokenTypes = (char **) malloc (sizeof(char *) * keyTypeNum);

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
            goto loser;
        }
        RA::Debug("RA_Enroll_Processor::ProcessRenewal", "keyType == %s ", keyTypeValue);

        // e.g. op.enroll.userKey.renewal.signing.enable=true
        PR_snprintf(configname, 256, "op.enroll.%s.renewal.%s.enable", tokenType, keyTypeValue);
        renewable = RA::GetConfigStore()->GetConfigAsBool(configname);

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
 
            tokenTypes[i] = tokenType;
            char **attr = (char **) malloc (sizeof(char *) * keyTypeNum);
            if (rc == LDAP_SUCCESS) {
                bool renewed = false;
                const char *caconnid;
                const char *profileId;
        PR_snprintf(configname, 256, "op.enroll.%s.renewal.%s.enable", tokenType, keyTypeValue);
        renewable = RA::GetConfigStore()->GetConfigAsBool(configname);
//                char *label;
    PR_snprintf((char *)configname, 256,"op.enroll.%s.renewal.%s.certId", tokenType, keyTypeValue);
    const char *certId = RA::GetConfigStore()->GetConfigAsString(configname, "C0");
    PR_snprintf((char *)configname, 256, "op.enroll.%s.renewal.%s.certAttrId", tokenType, keyTypeValue);
    const char *certAttrId = RA::GetConfigStore()->GetConfigAsString(configname, "c0");

                LDAPMessage *e= NULL;
                char *attr_status = NULL;
                for( e = RA::ra_get_first_entry( result );
                       e != NULL;
                       e = RA::ra_get_next_entry( e ) ) {
                    attr_status = RA::ra_get_cert_status( e );
                    if( (strcmp( attr_status, "revoked" ) == 0) ||
                        (strcmp( attr_status, "renewed" ) == 0) ) {

                        continue;
                    }

                    const char *label= NULL;
                    const char *pattern= NULL;
                    char *tmp_c = NULL;

                    // retrieve the most recent certificate to start

                    CERTCertificate **certs = RA::ra_get_certificates(e);
                    CERTCertificate *o_cert = NULL;
                    if (certs[0] != NULL) {
                        Buffer *keyid=NULL;
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
                            goto rloser;
                        }

                        RA::Debug("RA_Enroll_Processor::ProcessRenewal","got profileId=%s",profileId);
//cfu 1
			RA::Debug("RA_Enroll_Processor::ProcessRenewal", "begin renewal");
                        // send renewal request to CA
                        // o_cert is the cert gotten back
                        r = DoRenewal(caconnid, profileId, certs[0], &o_cert);
                        if (r == false) {
			    RA::Debug("RA_Enroll_Processor::ProcessRenewal", "after DoRenewal");
                            goto rloser;
                        }

                        // got cert... 

                        // build label
                        PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label", 
		                OP_PREFIX, tokenType, keyTypeValue);
                        RA::Debug(LL_PER_CONNECTION,FN,
		                "label '%s'", configname);
                        pattern = RA::GetConfigStore()->GetConfigAsString(configname);
			label = MapPattern(&nv, (char *) pattern);

			if (o_cert != NULL) {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "got cert!!");
			  tmp_c = NSSBase64_EncodeItem(0, 0, 0, &(o_cert)->derCert);
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "after NSSBase64_EncodeItem");
			} else {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "no cert!!");
			  goto rloser;
			}

			if ((tmp_c == NULL) || (tmp_c =="")) {
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "NSSBase64_EncodeItem failed");
			  goto rloser;
			}
			RA::Debug("RA_Enroll_Processor::ProcessRenewal", "NSSBase64_EncodeItem succeeded");
			attr[0] = PL_strdup(tmp_c);
			RA::Debug("RA_Enroll_Processor::ProcessRenewal", "b64 encoded cert =%s",attr[0]);

                        ktypes[i] = strdup(keyTypeValue);
                        origins[i] = strdup(cuid);
                        certificates[i] = o_cert;

			{
			  Buffer *certbuf = new Buffer(o_cert->derCert.data, o_cert->derCert.len);
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (certId[0] << 24) +
							   (certId[1] << 16),
							   certbuf);
			  pkcs11objx->AddObjectSpec(objSpec);
			}

                        if (o_cert->subjectKeyID.data != NULL) {
                          keyid = new Buffer((BYTE*)o_cert->subjectKeyID.data,
                                    (unsigned int)o_cert->subjectKeyID.len);
                        } else {// should always have keyid
			  RA::Debug("RA_Enroll_Processor::ProcessRenewal", "no subjectKeyID found in cert");
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
                        renewed = true;

		    rloser:

			if( attr[0] != NULL ) {
			  PR_Free(attr[0]);
			  attr[0] = NULL;
			}
			if( label != NULL ) {
			  PL_strfree( (char *) label );
			  label = NULL;
			}
			if( tmp_c != NULL ) {
			  PL_strfree( (char *) tmp_c );
			  tmp_c = NULL;
			}
                    }
                    break;
                  } //for
                  if((strcmp( attr_status, "active" ) == 0) &&
                       renewed) {
                      char *cn = RA::ra_get_cert_cn(e);
                      RA::ra_update_cert_status(cn, "renewed");
                      if( attr_status != NULL ) {
                          PL_strfree( attr_status );
                          attr_status = NULL;
                      }
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
    if( pretty_cuid != NULL ) {
        PR_Free( (char *) pretty_cuid );
        pretty_cuid = NULL;
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
    char *o_pub = NULL;
    char *o_priv = NULL;
    const char *connid = NULL;
    bool tksServerKeygen = false;
    bool serverKeygen = false;
    bool archive = false;
    const char *pretty_cuid = NULL;

    int i = 0;
    const char *FN="RA_Enroll_Processor::ProcessRecovery";

    PR_snprintf(configname, 256, "op.enroll.%s.keyGen.recovery.%s.keyType.num",
      tokenType, reason);
    int keyTypeNum = RA::GetConfigStore()->GetConfigAsInt(configname, -1);
    if (keyTypeNum == -1) {
        RA::Debug("RA_Enroll_Processor::ProcessRecovery", "Missing the configuration parameter for %s", configname);
        r = false;
        o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
        goto loser;
    }

RA::Debug("RA_Enroll_Processor::ProcessRecovery", "keyTypenum=%d", keyTypeNum);

    o_certNums = keyTypeNum;
    certificates = (CERTCertificate **) malloc (sizeof(CERTCertificate *) * keyTypeNum);
    ktypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    origins = (char **) malloc (sizeof(char *) * keyTypeNum);
    tokenTypes = (char **) malloc (sizeof(char *) * keyTypeNum);
    for (i=0; i<keyTypeNum; i++) {
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


        if (PL_strcasecmp(scheme, "GenerateNewKey") == 0) {
            RA::Debug("RA_Enroll_Processor::ProcessRecovery", "Generate new key for %s", keyTypeValue);
            r = GenerateCertificate(login, keyTypeNum, keyTypeValue, i, session, origins, ktypes, tokenType,
              pkcs11objx, pkcs11obj_enable, extensions, channel, wrapped_challenge,
              key_check, plaintext_challenge, cuid, msn, final_applet_version,
              khex, userid, o_status, certificates);
            tokenTypes[i] = PL_strdup(tokenType);
            if (o_status == STATUS_NO_ERROR)
                o_status = STATUS_ERROR_RECOVERY_IS_PROCESSED;
        } else if (PL_strcasecmp(scheme, "RecoverLast") == 0) {
            RA::Debug("RA_Enroll_Processor::RecoverLast", "Recover the key for %s", keyTypeValue);
            PR_snprintf(filter, 256, "(&(tokenKeyType=%s)(tokenID=%s))",
              keyTypeValue, lostTokenCUID);       
            int rc = RA::ra_find_tus_certificate_entries_by_order_no_vlv(filter,
              &result, 1);
 
            tokenTypes[i] = PL_strdup(origTokenType);
            char **attr = (char **) malloc (sizeof(char *) * keyTypeNum);
            if (rc == LDAP_SUCCESS) {
                // retrieve the most recent certificate, we just recover the most
                // recent one
                LDAPMessage *e = RA::ra_get_first_entry(result);
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
                            goto loser;
                        }
       
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "begin recovery code");

			SECKEYPublicKey *pk_p = NULL;
			SECItem si_mod;
			Buffer *modulus=NULL;
			SECItem *si_kid = NULL;
			Buffer *keyid=NULL;
			SECItem si_exp;
			Buffer *exponent=NULL;
	CERTSubjectPublicKeyInfo*  spkix = NULL;

			/*XXX should decide later whether some of the following should
			  be stored with token entry during enrollment*/
			int keysize = 1024; //XXX hardcode for now
			int pubKeyNumber = 5; //XXX hardcode for now
			int priKeyNumber = 4; //XXX hardcode for now
			int keyUsage = 0; //XXX hardcode for now
			int keyUser = 0; //XXX hardcode for now
			const char *certId="C2";
			const char *certAttrId="c2";
			const char *privateKeyAttrId="k4";
			const char *publicKeyAttrId="k5";

            PR_snprintf((char *)configname, 256, "%s.%s.keyGen.%s.label", 
		            OP_PREFIX, tokenType, keyTypeValue);
            RA::Debug(LL_PER_CONNECTION,FN,
		        "label '%s'", configname);
            const char *pattern = RA::GetConfigStore()->GetConfigAsString(configname);
			const char* label = MapPattern(&nv, (char *) pattern);

			//XXX these attr functions shouldn't take config params
            PR_snprintf(keyTypePrefix, 256, "op.enroll.%s.keyGen.encryption", tokenType);

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
			  goto rloser;
			}

			if ((tmp_c == NULL) || (tmp_c =="")) {
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "NSSBase64_EncodeItem failed");
			  goto rloser;
			}
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "NSSBase64_EncodeItem succeeded");
			attr[0] = PL_strdup(tmp_c);
			RA::Debug("RA_Enroll_Processor::ProcessRecovery", "b64 encoded cert =%s",attr[0]);
			
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
			    goto rloser;
                        }
                        
                        if (tksServerKeygen && archive && serverKeygen) {
                            RA::RecoverKey(session, lostTokenCUID, userid, 
				                           channel->getDrmWrappedDESKey(),
				                           attr[0], &o_pub, &o_priv,
				                           (char *)drmconnid);
                        } else {
			    r = false;
			    o_status = STATUS_ERROR_KEY_ARCHIVE_OFF;
                            RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::ProcessRecovery", "Archival is turned off");
			    goto rloser;
                        }

			if (o_pub == NULL) {
			  RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::DoEnrollment()", "RecoverKey called, o_pub is NULL");
			  r = false;
			  o_status = STATUS_ERROR_RECOVERY_FAILED;
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
			  RA::Debug(LL_PER_PDU, "DoEnrollment", "o_priv = %s", o_priv);


			RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::ProcessRecovery()", "key injection for RecoverKey occurs here");
			/*
			 * the following code converts b64-encoded public key info into SECKEYPublicKey
			 */
			SECStatus rv;
			SECItem der;
			CERTSubjectPublicKeyInfo*  spki;
               
			der.type = (SECItemType) 0; /* initialize it, since convertAsciiToItem does not set it */
			rv = ATOB_ConvertAsciiToItem (&der, o_pub);
			if (rv != SECSuccess){
			  RA::Debug("RA_Enroll_Processor::ProcessRecovery", "after converting public key, rv is failure");
			  SECITEM_FreeItem(&der, PR_FALSE);
			  r = false;
			  o_status = STATUS_ERROR_RECOVERY_FAILED;
			  goto rloser;
			}else {
			  RA::Debug(LL_PER_PDU, "ProcessRecovery", "item len=%d, item type=%d",der.len, der.type);

			  spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der);
			  SECITEM_FreeItem(&der, PR_FALSE);

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
			SECKEY_DestroySubjectPublicKeyInfo(spki);

			if( pk_p == NULL ) {
			    RA::Debug("RA_Enroll_Processor::ProcessRecovery",
                          "pk_p is NULL; unable to continue");
			    r = false;
			    o_status = STATUS_ERROR_RECOVERY_FAILED;
			    goto rloser;
            }

			/* fill in keyid, modulus, and exponent */

			si_mod = pk_p->u.rsa.modulus;
			modulus = new Buffer((BYTE*) si_mod.data, si_mod.len);

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
			si_exp = pk_p->u.rsa.publicExponent;
			exponent =  new Buffer((BYTE*) si_exp.data, si_exp.len);

			RA::Debug(LL_PER_PDU, "RA_Enroll_Processor::Process",
				  " keyid, modulus and exponent are retrieved");

                        ktypes[i] = strdup(keyTypeValue);
                        // We now store the token id of the original token
                        // that generates this certificate so we can
                        // tell if the certificate should be operated
                        // on or not during formation operation
                        origins[i] = strdup(lostTokenCUID);
                        certificates[i] = certs[0];


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
			    goto rloser;
			  }

			  if (channel->WriteObject(objid, (BYTE*)priv_keyblob, priv_keyblob.size()) != 1) {
			    r = false;
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

			  //XXX need randomize this later
			  BYTE iv[] = {0x01, 0x01,0x01,0x01,0x01,0x01,0x01,0x01};

			  data =
			    Buffer((BYTE*)objid, 4)+ // object id
                            Buffer(1,alg) +
			//    Buffer(1, 0x08) + // key type is DES3: 8
			    Buffer(1, (BYTE) decodeKey->size()) + // 1 byte length
			    Buffer((BYTE *) *decodeKey, decodeKey->size())+ // key -encrypted to 3des block
			    // check size
			    // key check
			    Buffer(1, (BYTE) decodeKeyCheck->size()) + //keycheck size
			    Buffer((BYTE *) *decodeKeyCheck , decodeKeyCheck->size())+ // keycheck
			    Buffer(1, 0x08)+ // IV_Length
			    Buffer((BYTE*)iv, 8);

			  //      RA::DebugBuffer("cfu debug", "ImportKeyEnc data buffer =", &data);

			  delete decodeKey;
			  delete decodeKeyCheck;

			  if (channel->ImportKeyEnc((keyUser << 4)+priKeyNumber,
						    (keyUsage << 4)+pubKeyNumber, &data) != 1) {
			    r = false;
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
			  Buffer b = channel->CreatePKCS11PriKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
									    privateKeyAttrId, label, keyid, modulus, OP_PREFIX, 
									    tokenType, keyTypePrefix);
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (privateKeyAttrId[0] << 24) +
							   (privateKeyAttrId[1] << 16),
							   &b);
			  pkcs11objx->AddObjectSpec(objSpec);
			}

			{
			  Buffer b = channel->CreatePKCS11PubKeyAttrsBuffer(KEY_TYPE_ENCRYPTION, 
									    publicKeyAttrId, label, keyid, 
									    exponent, modulus, OP_PREFIX, tokenType, keyTypePrefix);
			  ObjectSpec *objSpec = 
			    ObjectSpec::ParseFromTokenData(
							   (publicKeyAttrId[0] << 24) +
							   (publicKeyAttrId[1] << 16),
							   &b);
			  pkcs11objx->AddObjectSpec(objSpec);
			}
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
        } else {
	      RA::Debug("RA_Enroll_Processor::ProcessRecovery", 
		    "Misconfigure parameter for %s", configname);
	      r = false;
	      o_status = STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND;
	      goto loser;
        }
    }

 loser:
    if( pretty_cuid != NULL ) {
        PR_Free( (char *) pretty_cuid );
        pretty_cuid = NULL;
    }

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
