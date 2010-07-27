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
#include "cms/HttpConnection.h"
#include "cms/CertEnroll.h"

// for public key processing
#include "pk11func.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "base64.h"
#include "nssb64.h"
#include "prlock.h"

#include "main/Memory.h"

Buffer * parseResponse(char * /*response*/);
ReturnStatus verifyProof(SECKEYPublicKey* , SECItem* ,
             unsigned short , unsigned char* ,
             unsigned char* );

#ifdef XP_WIN32
#define TOKENDB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TOKENDB_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs handle for Certificate Enrollment
 */
TOKENDB_PUBLIC CertEnroll::CertEnroll()
{
}

/**
 * Destructs handle for Certificate Enrollment
 */
TOKENDB_PUBLIC CertEnroll::~CertEnroll()
{
}

/**
 * Revokes a certificate in the CA
 * reason:
 *   0 = Unspecified
 *   1 = Key compromised
 *   2 = CA key compromised
 *   3 = Affiliation changed
 *   4 = Certificate superseded
 *   5 = Cessation of operation
 *   6 = Certificate is on hold
 * serialno: serial number in decimal
 */
TOKENDB_PUBLIC int CertEnroll::RevokeCertificate(const char *reason, const char *serialno, const char *connid, char *&o_status)
{
    char parameters[5000];
    char configname[5000];
    int num;

    PR_snprintf((char *)parameters, 5000, "op=revoke&revocationReason=%s&revokeAll=(certRecordId%%3D%s)&totalRecordCount=1", reason, serialno);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.revoke", connid);
    char *servletID = (char*)RA::GetConfigStore()->GetConfigAsString(configname);

    PSHttpResponse *resp =  sendReqToCA(servletID, parameters, connid);

    if (resp != NULL) {
        char *content = resp->getContent();
        char *p = strstr(content, "status=");
        num = *(p+7) - '0';
        RA::Debug("CertEnroll::RevokeCertificate", "serialno=%s reason=%s connid=%s status=%d", serialno, reason, connid, num);
        if (num != 0) {
            char *q = strstr(p, "error=");
            q = q+6;
            o_status = PL_strdup(q);
            RA::Debug("CertEnroll::RevokeCertificate", "status string=%s", q);
        }
        if (content != NULL) {
            resp->freeContent();
            content = NULL;
        }    
        delete resp;
        resp = NULL;
    } else {
        RA::Debug("CertEnroll::RevokeCertificate", "serialno=%s reason=%s connid=%s failed: resp is NULL");
        o_status = PL_strdup("resp from sendReqToCA is NULL");
        num = 1;  //non-zero
    }
    return num;
}

TOKENDB_PUBLIC int CertEnroll::UnrevokeCertificate(const char *serialno, const char *connid,
  char *&o_status)
{
    char parameters[5000];
    char configname[5000];
    int num;

    PR_snprintf((char *)parameters, 5000, "serialNumber=%s",serialno);

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.unrevoke", connid);
    char *servletID = (char*)RA::GetConfigStore()->GetConfigAsString(configname);

    PSHttpResponse *resp =  sendReqToCA(servletID, parameters, connid);
    if (resp != NULL) {
        // XXX - need to parse response
        char *content = resp->getContent();
        char *p = strstr(content, "status=");
        num = *(p+7) - '0';
        RA::Debug("CertEnroll::UnrevokeCertificate", "status=%d", num);
        
        if (num != 0) {
            char *q = strstr(p, "error=");
            q = q+6;
            o_status = PL_strdup(q);
            RA::Debug("CertEnroll::UnrevokeCertificate", "status string=%s", q);
        }

        if (content != NULL) {
            resp->freeContent();
            content = NULL;
        }    
        delete resp;
        resp = NULL;
    }  else {
        RA::Debug("CertEnroll::UnrevokeCertificate", "serialno=%s reason=%s connid=%s failed: resp is NULL");
        o_status = PL_strdup("resp from sendReqToCA is NULL");
        num = 1;  //non-zero
    }

    return num;
}

TOKENDB_PUBLIC Buffer *CertEnroll::RenewCertificate(PRUint64 serialno, const char *connid, const char *profileId, char *error_msg)
{
    char parameters[5000];
    char configname[5000];

    RA::Debug("CertEnroll::RenewCertificate", "begins. profileId=%s",profileId);
    // on CA, renewal expects parameter "serial_num" if renew by serial number
    // ahh.  need to allow larger serialno...later
    PR_snprintf((char *)parameters, 5000, "serial_num=%u&profileId=%s&renewal=true",
               (int)serialno, profileId);
    RA::Debug("CertEnroll::RenewCertificate", "got parameters =%s", parameters);
    //e.g. conn.ca1.servlet.renewal=/ca/ee/ca/profileSubmitSSLClient
    PR_snprintf((char *)configname, 256, "conn.%s.servlet.renewal", connid);
    const char *servlet = RA::GetConfigStore()->GetConfigAsString(configname);
        if (servlet == NULL) {
            RA::Debug("CertEnroll::RenewCertificate",
                "Missing the configuration parameter for %s", configname);
            PR_snprintf(error_msg, 512, "Missing the configuration parameter for %s", configname);
            return NULL;
        }

    // on CA, same profile servlet processes the renewal as well as enrollment
    PSHttpResponse *resp =  sendReqToCA(servlet, parameters, connid);
    // XXX - need to parse response
    Buffer * certificate = NULL;
    if (resp != NULL) {
      RA::Debug(LL_PER_PDU, "CertEnroll::RenewCertificate",
          "sendReqToCA done");

      certificate = parseResponse(resp);
      RA::Debug(LL_PER_PDU, "CertEnroll::RenewCertificate",
          "parseResponse done");

      if( resp != NULL ) { 
          delete resp;
          resp = NULL;
      }
    } else {
      RA::Error("CertEnroll::RenewCertificate",
        "sendReqToCA failure");
      PR_snprintf(error_msg, 512, "sendReqToCA failure");
      return NULL;
    }

    return certificate;
}


/**
 * Sends certificate request to CA for enrollment.
 */
Buffer * CertEnroll::EnrollCertificate( 
					SECKEYPublicKey *pk_parsed,
					const char *profileId,
					const char *uid,
					const char *cuid /*token id*/,
					const char *connid, 
                                        char *error_msg,
                                        SECItem** encodedPublicKeyInfo)
{
    char parameters[5000];
 
    SECItem* si = SECKEY_EncodeDERSubjectPublicKeyInfo(pk_parsed);
    if (si == NULL) {

      RA::Error("CertEnroll::EnrollCertificate",
          "SECKEY_EncodeDERSubjectPublicKeyInfo  returns error");
      PR_snprintf(error_msg, 512, "SECKEY_EncodeDERSubjectPublicKeyInfo  returns error");
      return NULL;
    }

    // b64 encode it
    char* pk_b64 = BTOA_ConvertItemToAscii(si);

    if(encodedPublicKeyInfo == NULL)
    {
        if( si != NULL ) {
            SECITEM_FreeItem( si, PR_TRUE );
            si = NULL;
        }
    }
    else
    {

        *encodedPublicKeyInfo = si;

    }

    if (pk_b64 == NULL) {
    RA::Error(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "BTOA_ConvertItemToAscii returns error");

        PR_snprintf(error_msg, 512, "BTOA_ConvertItemToAscii returns error");
        return NULL;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "after BTOA_ConvertItemToAscii pk_b64=%s",pk_b64);

    char *url_pk = Util::URLEncode(pk_b64);
    char *url_uid = Util::URLEncode(uid);
    char *url_cuid = Util::URLEncode(cuid);
    const char *servlet;
    char configname[256];

    PR_snprintf((char *)configname, 256, "conn.%s.servlet.enrollment", connid);
    servlet = RA::GetConfigStore()->GetConfigAsString(configname);

    PR_snprintf((char *)parameters, 5000, "profileId=%s&tokencuid=%s&screenname=%s&publickey=%s", profileId, url_cuid, url_uid, url_pk);

    PSHttpResponse *resp =  sendReqToCA(servlet, parameters, connid);
    Buffer * certificate = NULL;
    if (resp != NULL) {
      RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "sendReqToCA done");

      certificate = parseResponse(resp);
      RA::Debug(LL_PER_PDU, "CertEnroll::EnrollCertificate",
          "parseResponse done");

      if( resp != NULL ) { 
          delete resp;
          resp = NULL;
      }
    } else {
      RA::Error("CertEnroll::EnrollCertificate",
        "sendReqToCA failure");
      PR_snprintf(error_msg, 512, "sendReqToCA failure");
      return NULL;
    }

    if( pk_b64 != NULL ) {
        PR_Free( pk_b64 );
        pk_b64 = NULL;
    }
    if( url_pk != NULL ) {
        PR_Free( url_pk );
        url_pk = NULL;
    }
    if( url_uid != NULL ) {
        PR_Free( url_uid );
        url_uid = NULL;
    }
    if( url_cuid != NULL ) {
        PR_Free( url_cuid );
        url_cuid = NULL;
    }

    return certificate;
}

/**
 * Extracts information from the public key blob and verify proof.
 *
 * Muscle Key Blob Format (RSA Public Key)
 * ---------------------------------------
 * 
 * The key generation operation places the newly generated key into
 * the output buffer encoding in the standard Muscle key blob format.
 *  For an RSA key the data is as follows:
 * 
 * Byte     Encoding (0 for plaintext)
 * 
 * Byte     Key Type (1 for RSA public)
 * 
 * Short     Key Length (1024 û high byte first)
 * 
 * Short     Modulus Length
 * 
 * Byte[]     Modulus
 * 
 * Short     Exponent Length
 * 
 * Byte[]     Exponent
 * 
 *  
 * Signature Format (Proof)
 * ---------------------------------------
 *  
 * The key generation operation creates a proof-of-location for the
 * newly generated key. This proof is a signature computed with the 
 * new private key using the RSA-with-MD5 signature algorithm.  The 
 * signature is computed over the Muscle Key Blob representation of 
 * the new public key and the challenge sent in the key generation 
 * request.  These two data fields are concatenated together to form
 * the input to the signature, without any other data or length fields.
 * 
 * Byte[]     Key Blob Data
 * 
 * Byte[]     Challenge
 * 
 * 
 * Key Generation Result
 * ---------------------------------------
 * 
 * The key generation command puts the key blob and the signature (proof)
 * into the output buffer using the following format:
 * 
 * Short     Length of the Key Blob
 * 
 * Byte[]     Key Blob Data
 * 
 * Short     Length of the Proof
 * 
 * Byte[]     Proof (Signature) Data
 *
 * @param blob the publickey blob to be parsed
 * @param challenge the challenge generated by RA
 * @return
 *      rc is 1 if success, -1 if failure
 *      pk is the public key resulted from parsing the blob.
 *
 ******/

SECKEYPublicKey *CertEnroll::ParsePublicKeyBlob(unsigned char *blob,
                             Buffer *challenge)
{
    char configname[5000];
    SECKEYPublicKey *pk = NULL;

    ReturnStatus rs;
    rs.status = PR_FAILURE;
    rs.statusNum = ::MSG_INVALID;

    if ((blob == NULL) || (challenge == NULL)) {
        RA::Error(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob", "invalid input");
	return NULL;
    }

    /*
     * decode blob into structures
     */

    // offset to the beginning of the public key length.  should be 0
    unsigned short pkeyb_len_offset = 0;

    unsigned short pkeyb_len = 0;
    unsigned char* pkeyb;
    unsigned short proofb_len = 0;
    unsigned char* proofb;

    /*
     * now, convert lengths
     */
    // 1st, keyblob length
    unsigned char len0 = blob[pkeyb_len_offset];
    unsigned char len1 = blob[pkeyb_len_offset +1];
    pkeyb_len = (unsigned short) ((len0 << 8) | (len1 & 0xFF));

    RA::Debug(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob",
          "pkeyb_len =%d",pkeyb_len);

    if (pkeyb_len <= 0) {
      RA::Error("CertEnroll::ParsePublicKeyBlob", "public key blob length = %d", pkeyb_len);
      return NULL;
    }
    // 2nd, proofblob length
    unsigned short proofb_len_offset = pkeyb_len_offset + 2 + pkeyb_len;
    len0 = blob[proofb_len_offset];
    len1 = blob[proofb_len_offset +1];
    proofb_len = (unsigned short) (len0 << 8 | len1 & 0xFF);
    RA::Debug(LL_PER_PDU, "CertEnroll::ParsePublicKeyBlob",
          "proofb_len =%d", proofb_len);

    // public key blob
    pkeyb = &blob[pkeyb_len_offset + 2];

    // proof blob
    proofb = &blob[proofb_len_offset + 2];

    SECItem siProof;
    siProof.type = (SECItemType) 0;
    siProof.data = (unsigned char *)proofb;
    siProof.len = proofb_len;

    // convert pkeyb to pkey
    // 1 byte encoding, 1 byte key type, 2 bytes key length, then the key
    unsigned short pkey_offset = 4;
    // now, convert lengths for modulus and exponent
    len0 = pkeyb[pkey_offset];
    len1 = pkeyb[pkey_offset + 1];
    unsigned short mod_len = (len0 << 8 | len1);

    len0 = pkeyb[pkey_offset + 2 + mod_len];
    len1 = pkeyb[pkey_offset + 2 + mod_len + 1];
    unsigned short exp_len = (len0 << 8 | len1);


    // public key mod blob
    unsigned char * modb = &pkeyb[pkey_offset + 2];

    // public key exp blob
    unsigned char * expb = &pkeyb[pkey_offset + 2 + mod_len + 2];

    // construct SECItem
    SECItem siMod;
    siMod.type = (SECItemType) 0;
    siMod.data = (unsigned char *) modb;
    siMod.len = mod_len;

    SECItem siExp;
    siExp.type = (SECItemType) 0;
    siExp.data = (unsigned char *)expb;
    siExp.len = exp_len;

    // construct SECKEYRSAPublicKeyStr
    SECKEYRSAPublicKeyStr rsa_pks;
    rsa_pks.modulus = siMod;
    rsa_pks.publicExponent = siExp;

    // construct SECKEYPublicKey
    // this is to be returned
    pk = (SECKEYPublicKey *) malloc(sizeof(SECKEYPublicKey));
    pk->keyType = rsaKey;
    pk->pkcs11Slot = NULL;
    pk->pkcs11ID = CK_INVALID_HANDLE;
    pk->u.rsa = rsa_pks;

    PR_snprintf((char *)configname, 256, "general.verifyProof");
    int verifyProofEnable = RA::GetConfigStore()->GetConfigAsInt(configname, 0x1);
    if (verifyProofEnable) {
      rs = verifyProof(pk, &siProof, pkeyb_len, pkeyb, challenge);
      if (rs.status == PR_FAILURE) {
        RA::Error("CertEnroll::ParsePublicKeyBlob",
          "verify proof failed");
        free(pk);
        pk = NULL;
      }
    }

    return pk;
}


/**
 * verify the proof.
 * @param pk the public key from the input blob
 * @param siProof the proof from the input blob
 * @param pkeyb_len the length of the publickey blob
 * @param pkeyb the public key blob
 * @param challenge the challenge generated by RA
 *
 * @return
 *      returns success indication in case of success
 *      returns error message number as defined in ReturnStatus in Base.h
 */
ReturnStatus CertEnroll::verifyProof(SECKEYPublicKey* pk, SECItem* siProof,
             unsigned short pkeyb_len, unsigned char* pkeyb,
             Buffer* challenge) {

    ReturnStatus rs;
    VFYContext * vc = NULL;
    rs.statusNum = ::VRFY_SUCCESS;
    rs.status = PR_SUCCESS;

    // verify proof (signature)
    RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
          "verify proof begins");

    vc = VFY_CreateContext(pk, siProof, SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE, NULL);

    if (vc == NULL) {
        RA::Error("CertEnroll::verifyProof",
        "VFY_CreateContext() failed");
        rs.status = PR_FAILURE;
        rs.statusNum = ::VFY_BEGIN_FAILURE;
        return rs;
    } else {
        RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
        "VFY_CreateContext() succeeded");
    }

    unsigned char proof[1024];
    int i =0; 
    for (i = 0; i<pkeyb_len; i++) {
        proof[i] = pkeyb[i];
    }
    //    RA::DebugBuffer("CertEnroll::VerifyProof","VerifyProof:: challenge =", challenge);
    unsigned char* chal = (unsigned char *)(BYTE *) (*challenge);
    unsigned int j = 0;
    for (j=0; j < challenge->size(); i++, j++) {
        proof[i] = chal[j];
	//	RA::Debug(LL_PER_PDU, "CertEnroll::VerifyProof","proof[%d]= %x",
	//		  i, proof[i]);
    }

    SECStatus vs = VFY_Begin(vc);
    if (vs == SECSuccess) {
      vs = VFY_Update(vc, (unsigned char *)proof , pkeyb_len + challenge->size());
      if (vs == SECSuccess) {
          vs = VFY_End(vc);
          if (vs == SECFailure) {
            RA::Error("CertEnroll::verifyProof",
                "VFY_End() failed pkeyb_len=%d challenge_size=%d", pkeyb_len, challenge->size());
            rs.statusNum = ::VFY_UPDATE_FAILURE;
            rs.status = PR_FAILURE;
          }
      } else {
          RA::Error("CertEnroll::verifyProof",
              "VFY_Update() failed");
          rs.statusNum = ::VFY_UPDATE_FAILURE;
          rs.status = PR_FAILURE;
      }
    } else {
      RA::Error("CertEnroll::verifyProof",
          "VFY_Begin() failed");

      rs.statusNum = ::VFY_BEGIN_FAILURE;
      rs.status = PR_FAILURE;
    }

    if( vc != NULL ) {
        VFY_DestroyContext( vc, PR_TRUE );
        vc = NULL;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::verifyProof",
        " VFY_End() returned %d",vs);

    return rs;

}

/**
 * sendReqToCA sends cert enrollment request via HTTPS to the CA
 * @param pk normalized public key
 * @param uid uid/screenname
 * @param cuid cud number of the client token
 * @param timeout timeout value for connection
 * @return
 *     PSHttpResponse if success
 *     NULL if failure
 */
PSHttpResponse * CertEnroll::sendReqToCA(const char *servlet, const char *parameters, const char *connid)
{
    // compose http uri

    RA::Debug(LL_PER_PDU, "CertEnroll::sendReqToCA",
          "begins");

    HttpConnection *caConn = RA::GetCAConn(connid);
    if (caConn == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::sendReqToCA", "Failed to get CA Connection %s", connid);
        RA::Error(LL_PER_PDU, "CertEnroll::sendReqToCA", "Failed to get CA Connection %s", connid);
        return NULL;
    }
    // PRLock *ca_lock = RA::GetCALock();
    int ca_curr = RA::GetCurrentIndex(caConn);
    int maxRetries = caConn->GetNumOfRetries();
    ConnectionInfo *connInfo = caConn->GetFailoverList();
    char **hostport = connInfo->GetHostPortList();
    int currRetries = 0;

    RA::Debug(LL_PER_PDU, "Before calling getResponse, caHostPort is %s", hostport[ca_curr]);

    PSHttpResponse * response = caConn->getResponse(ca_curr, servlet, parameters);
    while (response == NULL) {
        RA::Failover(caConn, connInfo->GetHostPortListLen());
        ca_curr = RA::GetCurrentIndex(caConn);

        if (++currRetries >= maxRetries) {
            RA::Debug(LL_PER_PDU, "Used up all the retries. Response is NULL","");
            RA::Error("CertEnroll::sendReqToCA", "Failed connecting to CA after %d retries", currRetries);
	    if (caConn != NULL) {
		    RA::ReturnCAConn(caConn);
	    }
            return NULL;
        }
        response = caConn->getResponse(ca_curr, servlet, parameters);
    }

    if (caConn != NULL) {
	    RA::ReturnCAConn(caConn);
    }
    return response;
}

/**
 * parse the http response and retrieve the certificate.
 * @param resp the response returned from http request
 * @return
 *      The certificate in Buffer if success
 *      NULL if failure
 */
Buffer * CertEnroll::parseResponse(PSHttpResponse * resp)
{
    unsigned int i;
    unsigned char blob[8192]; /* cert returned */
    int blob_len; /* cert length */
    char *certB64 = NULL;
    char *certB64End = NULL;
    unsigned int certB64Len = 0;
    Buffer *cert = NULL;
    char * response = NULL;
    SECItem * outItemOpt = NULL;
    
    if (resp == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "no response found");
	    return NULL;
    }
    response = resp->getContent();
    if (response == NULL) {
        RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "no content found");
	    return NULL;
    }

    // process result
    // first look for errorCode="" to look for success clue
    // and errorReason="..." to extract error reason
    char pattern[20] = "errorCode=\"0\"";
    char * err = strstr((char *)response, (char *)pattern);

    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "begin parsing");

    if (err == NULL) {
      RA::Error("CertEnroll::parseResponse",
		"can't find pattern for cert request response");
      goto endParseResp;
    }

    // if success, look for "outputList.outputVal=" to extract
    // the cert
    certB64 = strstr((char *)response, "outputVal=");
    certB64 = &certB64[11]; // point pass open "

    certB64End = strstr(certB64, "\";");
    *certB64End = '\0';

    certB64Len = strlen(certB64);
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "certB64 len = %d", certB64Len);

    for (i=0; i<certB64Len-1 ; i++) {
        if (certB64[i] == '\\') { certB64[i] = ' '; certB64[i+1] = ' '; }
    }

    // b64 decode and put back in blob
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "b64 decode received cert");

    outItemOpt = NSSBase64_DecodeBuffer(NULL, NULL, certB64, certB64Len);
    if (outItemOpt == NULL) {
        RA::Error("CertEnroll::parseResponse",
          "b64 decode failed");

	goto endParseResp;
    }
    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "b64 decode len =%d",outItemOpt->len);

    memcpy((char*)blob, (const char*)(outItemOpt->data), outItemOpt->len);
    blob_len = outItemOpt->len;

    cert = new Buffer((BYTE *) blob, blob_len);
    if( outItemOpt != NULL ) {
        SECITEM_FreeItem( outItemOpt, PR_TRUE );
        outItemOpt = NULL;
    }

    RA::Debug(LL_PER_PDU, "CertEnroll::parseResponse",
          "finished");

 endParseResp:
    resp->freeContent();
    return cert;
}

