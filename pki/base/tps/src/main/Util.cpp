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
#include "prmem.h"
#include "pk11func.h"
#include "main/Util.h"
#include "main/Buffer.h"
#include "engine/RA.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

TPS_PUBLIC Util::Util ()
{
}

TPS_PUBLIC Util::~Util ()
{
}

TPS_PUBLIC int Util::ascii2numeric (char c) 
{
    int num;
    switch (c) {
        case '0': case '1': case '2':case '3':case '4':case '5':
        case '6': case '7': case '8': case '9':
            num = c - '0';
            break;
        default:
            num = -1;
            break; 
    } 
    return num;
}

static BYTE ZERO[1] = { 0 };
static BYTE ONE[1] = { 1 };

TPS_PUBLIC BYTE* Util::bool2byte(bool b) {
    if (b)
        return ONE;
    else
        return ZERO;
}

static int isAlphaNumeric (char ch)
{
    return ((ch >='a') && (ch <= 'z') ||   /* logical AND &&, OR || */ 
  	    (ch >='A') && (ch <= 'Z') || 
	    (ch >='0') && (ch <= '9') );
}

static char bin2hex (BYTE ch)
{
    ch = ch & 0x0f; 
    ch += '0';
    if (ch > '9')
            ch += 7;
    return (ch);
}

static BYTE hex2bin (BYTE ch)
{
      if (ch > '9')
            ch = ch - 'A' + 10;
      else
            ch = ch - '0';
      return (ch);
}


TPS_PUBLIC char *Util::SpecialURLEncode(Buffer &data) {
        int i;
        BYTE *buf = (BYTE*)data;
        int len = (int)data.size();
        char *ret = NULL;
	int sum = 0;

        for (i = 0; i < len; i ++) {
                if (buf[i] == ' ') {
                        sum+=1;
                } else if (isAlphaNumeric(buf[i])) {
                        sum+=1;
                } else {
                        sum+=3;
                }
        }
	ret = (char *)PR_Malloc(sum + 1); // allocate more than we may need
	if (ret == NULL)
		return NULL;
        char *cur = ret;

        for (i = 0; i < len; i ++) {
                if (buf[i] == ' ') {
                        *cur++ = '+';
                } else if (isAlphaNumeric(buf[i])) {
                        *cur++ = buf[i];
                } else {
                        *cur++ = '#';
                        *cur++ = bin2hex(buf[i] >> 4);
                        *cur++ = bin2hex(buf[i]);
                }
        }
        *cur = '\0'; // null-terminated
        return ret;
}

TPS_PUBLIC char *Util::URLEncode (Buffer &data)
{
	int i;
	BYTE *buf = (BYTE*)data;
        int len = (int)data.size();
	int sum = 0;

	for (i = 0; i < len; i ++) {
                if (buf[i] == ' ') { 
			sum+=1;
		} else if (isAlphaNumeric(buf[i])) { 
			sum+=1;
		} else { 
			sum+=3;
		}
	}
	char *ret = (char *)PR_Malloc(sum + 1); // allocate more than we may need
	char *cur = ret;

	for (i = 0; i < len; i ++) {
                if (buf[i] == ' ') { 
			*cur++ = '+'; 
		} else if (isAlphaNumeric(buf[i])) { 
			*cur++ = buf[i]; 
		} else { 
			*cur++ = '%'; 
			*cur++ = bin2hex(buf[i] >> 4); 
			*cur++ = bin2hex(buf[i]); 
		}
	}
	*cur = '\0'; // null-terminated
	return ret;
}

TPS_PUBLIC char *Util::URLEncodeInHex (Buffer &data)
{
	int i;
	BYTE *buf = (BYTE*)data;
        int len = (int)data.size();
	int sum = 0;

	for (i = 0; i < len; i ++) {
		sum+=3;
	}

	char *ret = (char *)PR_Malloc(sum + 1); // allocate more than we may need
	char *cur = ret;

	for (i = 0; i < len; i ++) {
		*cur++ = '%'; 
		*cur++ = bin2hex(buf[i] >> 4); 
		*cur++ = bin2hex(buf[i]); 
	}
	*cur = '\0'; // null-terminated
	return ret;
}

TPS_PUBLIC char * Util::URLEncode1(const char *str)
{
	int sum = 0;
  if (str == NULL)
    return NULL;

    // URL-encode the base-64 encoded public key. This code copies
    // From input buffer str[] to output buffer encoded_str[]
    int i = 0;
    int j = 0;
    char c;

    i = 0;
    j = 0;
    while (1) {
        c = str[j];
        if (c == '/') {
            sum+=3;
        } else if (c == '=') {
            sum+=3;
        } else if (c == '\r') {
            sum+=3;
        } else if (c == '\n') {
            sum+=3;
        } else if (c == '+') {
            sum+=3;
        } else if (c == '&') {
            sum+=3;
        } else if (c == ' ') {
            sum+=1;
        } else {
            sum+=1;
        }
        if (c == '\0') {
            break;
        }
        i++;
        j++;
    }

  char *encoded_str = (char *)PR_Malloc(sum); //allocate more than we may need
  
  if (encoded_str == NULL)
	  return NULL;

    i = 0;
    j = 0;
    while (1) {
        c = str[j];
        if (c == '/') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '2';
            encoded_str[i] = 'F';
        } else if (c == '&') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '2';
            encoded_str[i] = '6';
        } else if (c == '=') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '3';
            encoded_str[i] = 'D';
        } else if (c == '\r') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '0';
            encoded_str[i] = 'D';
        } else if (c == '\n') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '0';
            encoded_str[i] = 'A';
        } else if (c == '+') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '2';
            encoded_str[i] = 'B';
        } else if (c == ' ') {
            encoded_str[i] = '+';
        } else {
            encoded_str[i] = str[j];
        }
        if (encoded_str[i] == '\0') {
            break;
        }
        i++;
        j++;
    }
    encoded_str[i] = '\0';

    // DONT print, some of the sensitive information get printed.
    /*
    RA::Debug(LL_PER_PDU, "CertEnroll::urlEncode",
          "URL-encoded encoded_str =%s",encoded_str);
    */

    return encoded_str;
}
/**
 * this urlEncode function takes a char string
 */
TPS_PUBLIC char * Util::URLEncode(const char *str)
{
	int sum = 0;
  if (str == NULL)
    return NULL;

    // URL-encode the base-64 encoded public key. This code copies
    // From input buffer str[] to output buffer encoded_str[]
    int i = 0;
    int j = 0;
    char c;

    i = 0;
    j = 0;
    while (1) {
        c = str[j];
        if (c == '/') {
            sum+=3;
        } else if (c == '=') {
            sum+=3;
        } else if (c == '\r') {
            sum+=3;
        } else if (c == '\n') {
            sum+=3;
        } else if (c == '+') {
            sum+=3;
        } else if (c == ' ') {
            sum+=1;
        } else {
            sum+=1;
        }
        if (c == '\0') {
            break;
        }
        i++;
        j++;
    }

  char *encoded_str = (char *)PR_Malloc(sum); //allocate more than we may need
  
  if (encoded_str == NULL)
	  return NULL;

    i = 0;
    j = 0;
    while (1) {
        c = str[j];
        if (c == '/') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '2';
            encoded_str[i] = 'F';
        } else if (c == '=') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '3';
            encoded_str[i] = 'D';
        } else if (c == '\r') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '0';
            encoded_str[i] = 'D';
        } else if (c == '\n') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '0';
            encoded_str[i] = 'A';
        } else if (c == '+') {
            encoded_str[i++] = '%';
            encoded_str[i++] = '2';
            encoded_str[i] = 'B';
        } else if (c == ' ') {
            encoded_str[i] = '+';
        } else {
            encoded_str[i] = str[j];
        }
        if (encoded_str[i] == '\0') {
            break;
        }
        i++;
        j++;
    }
    encoded_str[i] = '\0';

    // DONT print, some of the sensitive information get printed.
    /*
    RA::Debug(LL_PER_PDU, "CertEnroll::urlEncode",
          "URL-encoded encoded_str =%s",encoded_str);
    */

    return encoded_str;
}

/* s Format: 01AFEE */
TPS_PUBLIC Buffer *Util::Str2Buf (const char *s)
{
	int len = strlen(s) / 2;
        BYTE *ret = (BYTE *)PR_Malloc(len);
        if (ret == NULL)
                return NULL;

        for (int i = 0; i < len; i ++) {
               ret[i] = hex2bin(s[i*2]) * 16 + hex2bin(s[i*2+1]);
        }

	Buffer *newbuf = new Buffer(ret, len);
        if( ret != NULL ) {
            PR_Free( ret );
            ret = NULL;
        }
        return newbuf;
}

TPS_PUBLIC char *Util::Buffer2String (Buffer &data)
{
	int i;
	BYTE *buf = (BYTE*)data;
        int len = (int)data.size();
	int sum = 0;

	for (i = 0; i < len; i ++) {
		sum+=2;
	}
	char *ret = (char *)PR_Malloc(sum + 1); // allocate more than we may need
	if (ret == NULL)
		return NULL;
	char *cur = ret;

	for (i = 0; i < len; i ++) {
		*cur++ = bin2hex(buf[i] >> 4); 
		*cur++ = bin2hex(buf[i]); 
	}
	*cur = '\0'; // null-terminated
	return ret;
}

TPS_PUBLIC Buffer *Util::SpecialURLDecode(const char *data)
{
        int i;
        Buffer buf;
        Buffer *ret = NULL;
        int len = strlen(data);
        BYTE *tmp = NULL;
        int sum = 0;

        if (len == 0)
            return NULL;
        tmp = (BYTE *)malloc(len);
	if (tmp == NULL)
		return NULL;
        for (i = 0; i < len; i++) {
                if (data[i] == '+') {
                        tmp[sum++] = ' ';
                } else if (data[i] == '#') {
                        tmp[sum++] = (hex2bin(data[i+1]) << 4) + hex2bin(data[i+2]);
                        i+=2;
                } else {
                        tmp[sum++] = (BYTE)data[i];
                }
        }

        ret = new Buffer(tmp, sum);
        if( tmp != NULL ) {
            free( tmp );
            tmp = NULL;
        }
        return ret;
}

TPS_PUBLIC Buffer *Util::URLDecode(const char *data)
{
	int i;
	Buffer buf;
        Buffer *ret = NULL;
	int len = strlen(data);
	BYTE *tmp = NULL;
	int sum = 0;

        if (len == 0)
            return NULL;
        tmp = (BYTE *)PR_Malloc(len);
	for (i = 0; i < len; i++) {
		if (data[i] == '+') {
			tmp[sum++] = ' ';
		} else if (data[i] == '%') {
			tmp[sum++] = (hex2bin(data[i+1]) << 4) + hex2bin(data[i+2]);
			i+=2;
		} else {
			tmp[sum++] = (BYTE)data[i];
		}
	}	

        ret = new Buffer(tmp, sum);
        if( tmp != NULL ) {
            PR_Free( tmp );
            tmp = NULL;
        }
	return ret;
}


TPS_PUBLIC PRStatus Util::GetRandomChallenge(Buffer &random)
{
        PRStatus rv = PR_FAILURE;
	SECStatus status;

	status = PK11_GenerateRandom(random, random.size()); 
	if (status != SECSuccess) {
                goto loser;
        }
	rv = PR_SUCCESS;
loser:
        return rv;
} /* GetRandomChallenge */

#define DES2_WORKAROUND

TPS_PUBLIC PK11SymKey *Util::DiversifyKey(PK11SymKey *masterKey, Buffer &data, PK11SlotInfo *slot)
{
    PK11SymKey *key = NULL;
    PRStatus status = PR_FAILURE ;
    PK11Context *context = NULL;
#ifdef DES2_WORKAROUND
    unsigned char keyData[24];
#else
    unsigned char keyData[16];
#endif
    SECItem keyItem = { siBuffer, keyData, sizeof keyData };
    SECStatus s;
    int i;
    int len;
    static SECItem noParams = { siBuffer, 0, 0 };

    /* XXX 
           - masterKey could be just a double-length 
             DES Key (16 bytes).
           - we may need to add the first 8 bytes to
             the end to make the key 24 bytes long (DES3 Key)
     */
    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, 
                    masterKey,
                    &noParams);
    if (!context) goto done;

    /* Part 1 */
    s = PK11_CipherOp(context, &keyData[0], &len, 8, &((BYTE*)data)[0], 8);
    if (s != SECSuccess) goto done;

    /* Part 2 */
    s = PK11_CipherOp(context, &keyData[8], &len, 8, &((BYTE*)data)[8], 8);
    if (s != SECSuccess) goto done;

#ifdef DES2_WORKAROUND
    /* Part 3 */
    for(i = 0;i < 8;i++)
    {
        keyData[i+16] = keyData[i];
    }
#endif

    key = PK11_ImportSymKeyWithFlags(
                slot,
                CKM_DES3_ECB, 
                PK11_OriginGenerated,
                CKA_ENCRYPT, 
                &keyItem, CKF_SIGN | CKF_ENCRYPT, PR_FALSE, 0);

    status = PR_SUCCESS;
    
done:

    return key;
}

TPS_PUBLIC PRStatus Util::ComputeKeyCheck(const Buffer& newKey, Buffer& output)
{
    PK11SymKey *key = NULL;
    PRStatus status = PR_FAILURE ;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    SECStatus s = SECFailure;
    int len;
    static SECItem noParams = { siBuffer, 0, 0 };
#ifdef DES2_WORKAROUND
    unsigned char keyData[24];
#else
    unsigned char keyData[16];
#endif
    SECItem keyItem = {siBuffer, keyData, sizeof(keyData) };
    unsigned char value[8];
    // convert 16-byte to 24-byte triple-DES key
    memcpy(keyData, newKey, 16);
#ifdef DES2_WORKAROUND
    memcpy(keyData+16, newKey, 8);
#endif

    memset(value, 0, sizeof value);

    key = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
                   PK11_OriginGenerated, CKA_ENCRYPT, &keyItem,
                   CKF_ENCRYPT, PR_FALSE, 0);
    if( ! key ) {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, key,
                    &noParams);
    if (!context) {
        goto done;
    }
    s = PK11_CipherOp(context, &value[0], &len, 8, &value[0], 8);
    if (s != SECSuccess) {
        goto done;
    }

    output.resize(3);
    output.replace(0, value, 3);

    status = PR_SUCCESS;
done:
    memset(keyData, 0, sizeof keyData);
    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }
    if( slot != NULL ) {
        PK11_FreeSlot( slot );
        slot = NULL;
    }
    if( key != NULL ) {
        PK11_FreeSymKey( key );
        key = NULL;
    }

    return status;
}

TPS_PUBLIC PRStatus Util::ComputeCryptogram(PK11SymKey *key, 
	const Buffer &card_challenge, const Buffer &host_challenge,
	Buffer &output)
{
	Buffer icv(8, (BYTE)0);
	Buffer input = card_challenge + host_challenge;

	return ComputeMAC(key, input, icv, output);
} /* ComputeCryptogram */


TPS_PUBLIC PRStatus Util::ComputeMAC(PK11SymKey *key, Buffer &x_input, 
		const Buffer &icv, Buffer &output)
{
    PRStatus rv = PR_SUCCESS;
    PK11Context *context = NULL;
//    NetkeyICV temp;
    unsigned char result[8];
    int i;
    SECStatus s;
    int len;
#ifdef USE_DESMAC
    CK_ULONG macLen = sizeof result;
    SECItem params = { siBuffer, (unsigned char *)&macLen, sizeof macLen };
#endif
    static SECItem noParams = { siBuffer, 0, 0 };
    static unsigned char macPad[] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    BYTE *input = (BYTE *) x_input;	
    int inputLen = x_input.size();

#ifdef USE_DESMAC
    context = PK11_CreateContextBySymKey(CKM_DES3_MAC_GENERAL, CKA_SIGN,
                                key, &params);
    if (!context) { rv = PR_FAILURE; goto done; }

    s = PK11_DigestBegin(context);
    if (s != SECSuccess) { rv = PR_FAILURE; goto done; }

    s = PK11_DigestOp(context, icv, 8);
    if (s != SECSuccess) { rv = PR_FAILURE; goto done; }

    while(inputLen >= 8)
    {
        s = PK11_DigestOp(context, input, 8);
        if (s != SECSuccess) { rv = PR_FAILURE; goto done; }

        input += 8;
        inputLen -= 8;
    }

    for (i = 0;i < inputLen;i++)
    {
        result[i] = input[i];
    }

    input = macPad;
    for(;i < 8;i++)
    {
        result[i] = *input++;
    }

    s = PK11_DigestOp(context, result, sizeof result);
    if (s != SECSuccess) { rv = PR_FAILURE; goto done; }

    s = PK11_DigestFinal(context, output, (unsigned int *)&len, sizeof output);
    if (1 != SECSuccess) { rv = PR_FAILURE; goto done; }

#else

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, key, &noParams);
    if (!context) { rv = PR_FAILURE; goto done; }

    memcpy(result, icv, sizeof result);

    /* Process whole blocks */
    while(inputLen >= 8)
    {
        for(i = 0;i < 8;i++)
        {
            result[i] ^= input[i];
        }

        s = PK11_CipherOp(context, result, &len, sizeof result, result, sizeof result);
        if (s != SECSuccess) { rv = PR_FAILURE; goto done; }
        if (len != sizeof result) /* assert? */
        {
            //PR_SetError(PR_UNKNOWN_ERROR, 0);
            rv = PR_FAILURE;
            goto done;
        }

        input += 8;
        inputLen -= 8;
    }

    /*
     * Fold in remaining data (if any)
     * Set i to number of bytes processed
     */
    for(i = 0;i < inputLen;i++)
    {
        result[i] ^= input[i];
    }

    /*
     * Fill remainder of last block. There
     * will be at least one byte handled here.
     */
    input = macPad;
    while(i < 8)
    {
        result[i] ^= *input++;
        i++;
    }

    s = PK11_CipherOp(context, result, &len, sizeof result, result, sizeof result);
    if (s != SECSuccess) { rv = PR_FAILURE; goto done; }
    if (len != sizeof result)
    {
        //PR_SetError(PR_UNKNOWN_ERROR, 0);
        rv = PR_FAILURE;
        goto done;
    }

    output.replace(0, result, sizeof result);
#endif

done:
    if( context != NULL )
    {
        PK11_Finalize( context );
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }
    memset(result, 0, sizeof result);

    return rv;
} /* ComputeMAC */

TPS_PUBLIC PK11SymKey *Util::DeriveKey(const Buffer& permKey,
                        const Buffer& hostChallenge,
                        const Buffer& cardChallenge)
{
    PK11SymKey *key = NULL, *master = NULL;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    unsigned char derivationData[16];
#ifdef DES2_WORKAROUND
    unsigned char keyData[24];
#else
    unsigned char keyData[16];
#endif
    int i;
    SECStatus s;
    int len;
    SECItem keyItem = { siBuffer, keyData, sizeof keyData };
    static SECItem noParams = { siBuffer, 0, 0 };
    BYTE masterKeyData[24];
    SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData) };

    // convert 16-byte to 24-byte triple-DES key
    memcpy(masterKeyData, permKey, 16);
    memcpy(masterKeyData+16, permKey, 8);

    master = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
                   PK11_OriginGenerated, CKA_ENCRYPT, &masterKeyItem,
                   CKF_ENCRYPT, PR_FALSE, 0);
    if( ! master ) goto done;

    for(i = 0;i < 4;i++)
    {
        derivationData[i] = cardChallenge[i+4];
        derivationData[i+4] = hostChallenge[i];
        derivationData[i+8] = cardChallenge[i];
        derivationData[i+12] = hostChallenge[i+4];
    }
    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
                    &noParams);
    if (!context) goto done;

    /* Part 1 */
    s = PK11_CipherOp(context, &keyData[0], &len, 8, &derivationData[0], 8);
    if (s != SECSuccess) goto done;

    /* Part 2 */
    s = PK11_CipherOp(context, &keyData[8], &len, 8, &derivationData[8], 8);
    if (s != SECSuccess) goto done;

#ifdef DES2_WORKAROUND
    /* Part 3 */
    for(i = 0;i < 8;i++)
    {
        keyData[i+16] = keyData[i];
    }
#endif

    key = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB, PK11_OriginGenerated,
                   CKA_ENCRYPT, &keyItem, CKF_SIGN | CKF_ENCRYPT, PR_FALSE, 0);

done:
    memset(keyData, 0, sizeof keyData);
    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }
    if( slot != NULL ) {
        PK11_FreeSlot( slot );
        slot = NULL;
    }
    if( master != NULL ) {
        PK11_FreeSymKey( master );
        master = NULL;
    }

    return key;
}

/**
 *
 * 01 
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (AUTH KEY)
 * 1B C8 4B 1C 31 
 * 03 8B AF 47
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (MAC KEY) 
 * 1B C8 4B 1C 31 
 * 03 8B AF 47  
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (KEK KEY)
 * 1B C8 4B 1C 31 
 * 03 8B AF 47 
 *
 */
TPS_PUBLIC PRStatus Util::CreateKeySetData(Buffer &newMasterVer, Buffer &old_kek_key, Buffer &new_auth_key, Buffer &new_mac_key, Buffer &new_kek_key, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    Buffer result;

    Buffer encrypted_auth_key(16);
    Util::EncryptData(old_kek_key, new_auth_key, encrypted_auth_key);
    Buffer kc_auth_key(3);
    Util::ComputeKeyCheck(new_auth_key, kc_auth_key);
    Buffer encrypted_mac_key(16);
    Util::EncryptData(old_kek_key, new_mac_key, encrypted_mac_key);
    Buffer kc_mac_key(3);
    Util::ComputeKeyCheck(new_mac_key, kc_mac_key);
    Buffer encrypted_kek_key(16);
    Util::EncryptData(old_kek_key, new_auth_key, encrypted_kek_key);
    Buffer kc_kek_key(3);
    Util::ComputeKeyCheck(new_kek_key, kc_kek_key);

    result = newMasterVer +
          Buffer(1, (BYTE)0x81) +
          Buffer(1, (BYTE)0x10) +
          encrypted_auth_key +
          Buffer(1, (BYTE)0x03) +
          kc_auth_key +
          Buffer(1, (BYTE)0x81) +
          Buffer(1, (BYTE)0x10) +
          encrypted_mac_key +
          Buffer(1, (BYTE)0x03) +
          kc_mac_key +
          Buffer(1, (BYTE)0x81) +
          Buffer(1, (BYTE)0x10) +
          encrypted_kek_key +
          Buffer(1, (BYTE)0x03) +
          kc_kek_key;

    output = result;

    rv = PR_SUCCESS;
    return rv;
}


/*
 * for Secure Messaging in Secure Channel
 */
TPS_PUBLIC PRStatus Util::EncryptData(PK11SymKey *encSessionKey,
			   Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;
    SECStatus s = SECFailure;
    //static SECItem noParams = { siBuffer, 0, 0 };
    static unsigned char d[8] = { 0,0,0,0,0,0,0,0 };
    static SECItem ivParams = { siBuffer, d, 8 };
    PK11Context *context = NULL;
    unsigned char result[8];
    int len;
    int i;

    /* this is ECB mode
    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, encSessionKey,
                    &noParams);
    */
    // use CBC mode
    context = PK11_CreateContextBySymKey(CKM_DES3_CBC, CKA_ENCRYPT, encSessionKey,
                    &ivParams);
    if (!context) {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8) {
        s = PK11_CipherOp(context, result, &len, 8,
                (unsigned char *)(((BYTE*)input)+i), 8);

        if (s != SECSuccess) {
            goto done;
        }
	output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;
//    RA::Debug("Util::EncryptData", "success");
done:

    //#define VRFY_ENC_SESSION_KEY
    // fix this to use CBC mode later
#ifdef VRFY_ENC_SESSION_KEY
    Buffer enc_key_buffer = Buffer((BYTE *) PK11_GetKeyData(encSessionKey)->data, PK11_GetKeyData(encSessionKey)->len);
        RA::DebugBuffer("Util::EncryptData", "Verifying Encrypted Data",
		&output);
        Buffer out1 = Buffer(16, (BYTE)0);
	PRStatus status = Util::DecryptData(enc_key_buffer, output, out1);
        RA::DebugBuffer("Util::EncryptData", "Decrypted Data",
		&out1);
#endif


    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }

    return rv;
}


TPS_PUBLIC PRStatus Util::EncryptData(Buffer &kek_key, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11SymKey *master = NULL;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    int i;
    SECStatus s = SECFailure;
    int len;
    static SECItem noParams = { siBuffer, 0, 0 };
#ifdef DES2_WORKAROUND
    unsigned char masterKeyData[24];
#else
    unsigned char masterKeyData[16];
#endif
    SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData) };
    unsigned char result[8];

    // convert 16-byte to 24-byte triple-DES key
    memcpy(masterKeyData, (BYTE*)kek_key, 16);
#ifdef DES2_WORKAROUND
    memcpy(masterKeyData+16, (BYTE*)kek_key, 8);
#endif

    master = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
                   PK11_OriginGenerated, CKA_ENCRYPT, &masterKeyItem,
                   CKF_ENCRYPT, PR_FALSE, 0);
    if( ! master ) {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
                    &noParams);
    if (!context) {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8) {
        s = PK11_CipherOp(context, result, &len, 8,
                (unsigned char *)(((BYTE*)input)+i), 8);

        if (s != SECSuccess) {
            goto done;
        }
	output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;

done:

    memset(masterKeyData, 0, sizeof masterKeyData);
    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }
    if( slot != NULL ) {
        PK11_FreeSlot( slot );
        slot = NULL;
    }
    if( master != NULL ) {
        PK11_FreeSymKey( master );
        master = NULL;
    }

    return rv;
}

TPS_PUBLIC PRStatus Util::DecryptData(Buffer &kek_key, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11SymKey *master = NULL;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    int i;
    SECStatus s = SECFailure;
    int len;
    static SECItem noParams = { siBuffer, 0, 0 };
#ifdef DES2_WORKAROUND
    unsigned char masterKeyData[24];
#else
    unsigned char masterKeyData[16];
#endif
    SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData) };
    unsigned char result[8];

    // convert 16-byte to 24-byte triple-DES key
    memcpy(masterKeyData, (BYTE*)kek_key, 16);
#ifdef DES2_WORKAROUND
    memcpy(masterKeyData+16, (BYTE*)kek_key, 8);
#endif

    master = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
                   PK11_OriginGenerated, CKA_DECRYPT, &masterKeyItem,
                   CKF_DECRYPT, PR_FALSE, 0);
    if( ! master ) {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_DECRYPT, master,
                    &noParams);
    if (!context) {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8) {
        s = PK11_CipherOp(context, result, &len, 8,
                (unsigned char *)(((BYTE *)input)+i), 8);

        if (s != SECSuccess) {
            goto done;
        }
	output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;

done:

    memset(masterKeyData, 0, sizeof masterKeyData);
    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }
    if( slot != NULL ) {
        PK11_FreeSlot( slot );
        slot = NULL;
    }
    if( master != NULL ) {
        PK11_FreeSymKey( master );
        master = NULL;
    }

    return rv;
}

// this one takes PK11SymKey instead
TPS_PUBLIC PRStatus Util::DecryptData(PK11SymKey* enc_key, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11Context *context = NULL;
    int i;
    SECStatus s = SECFailure;
    int len;
    //    static SECItem noParams = { siBuffer, 0, 0 };
    static unsigned char d[8] = { 0,0,0,0,0,0,0,0 };
    static SECItem ivParams = { siBuffer, d, 8 };
    unsigned char result[8];

    if( ! enc_key ) {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_CBC, CKA_DECRYPT, enc_key,
                    &ivParams);
    if (!context) {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8) {
        s = PK11_CipherOp(context, result, &len, 8,
                (unsigned char *)(((BYTE *)input)+i), 8);

        if (s != SECSuccess) {
            goto done;
        }
	output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;

done:

    if( context != NULL ) {
        PK11_DestroyContext( context, PR_TRUE );
        context = NULL;
    }

    return rv;
}

