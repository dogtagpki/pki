// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifdef __cplusplus
extern "C"
{
#endif
#include "pk11func.h"
#include "nspr.h"
#ifdef __cplusplus
#include <jni.h>
#include <assert.h>
#include <string.h>

}
#endif
#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include <cstdarg>
#include <string>
#include <stdlib.h>
#include "Buffer.h"
#include "SymKey.h"
#define DES2_WORKAROUND

PRFileDesc *d = NULL;

/**
 *  Encrypt 'cc_len' bytes of data in 'input' with key kek_key.
 *  Result goes into buffer 'output'
 *  Returns PR_FAILURE if there was an error
 */
PRStatus EncryptData(const Buffer &kek_key, jbyte * input,int cc_len, Buffer &output)
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
    memcpy(masterKeyData, kek_key, 16);
#ifdef DES2_WORKAROUND
    memcpy(masterKeyData+16, kek_key, 8);
#endif

    master = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
        PK11_OriginGenerated, CKA_ENCRYPT, &masterKeyItem,
        CKF_ENCRYPT, PR_FALSE, 0);
    if (master == NULL)
    {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
        &noParams);
    if (context == NULL)
    {
        goto done;
    }

    for(i = 0;i < (int)cc_len;i += 8)
    {
        s = PK11_CipherOp(context, result, &len, 8,
            (unsigned char *)(input+i), 8);

        if (s != SECSuccess)
        {
            goto done;
        }
        output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;

done:
    /* memset(masterKeyData, 0, sizeof masterKeyData); */
    if (context != NULL)
    {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }
    if (slot != NULL)
    {
        PK11_FreeSlot(slot);
        slot = NULL;
    }
    if (master != NULL)
    {
        PK11_FreeSymKey(master);
        master = NULL;
    }

    return rv;
}

void GetKeyName(jbyte *keyVersion, char *keyname)
{
    int index=0;
    if(strlen(masterKeyPrefix)!=0)
    {
        index= strlen(masterKeyPrefix);
        strcpy(keyname,masterKeyPrefix);
    }
    keyname[index+0]='#';
    sprintf(keyname+index+1,"%.2d", keyVersion[0]);
    keyname[index+3]='#';
    sprintf(keyname+index+4,"%.2d", keyVersion[1]);
}


extern "C"  JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_EncryptData
(JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring);

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_EncryptData(JNIEnv * env, jclass this2, jstring j_tokenName, jstring j_keyName, jbyteArray  j_in, jbyteArray keyInfo, jbyteArray CUID, jbyteArray kekKeyArray, jstring useSoftToken_s)
{
    int status = PR_FAILURE;
    jbyte * kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    jbyte * keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte * cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( j_in, NULL);
    int cc_len =  (env)->GetArrayLength(j_in);

    Buffer kek_buffer = Buffer((BYTE*)kek_key, 16);
    Buffer out = Buffer(16, (BYTE)0);

    /* generate kek key */
    /* identify the masterKey by KeyInfo in TKS */
    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    GetDiversificationData(cuidValue,kekData,kek);

    PK11SlotInfo *slot = NULL;
    if(j_tokenName != NULL)
    {
        char *tokenNameChars = (char *)(env)->GetStringUTFChars(j_tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(j_tokenName, (const char *)tokenNameChars);
        tokenNameChars = NULL;
    }

    if(j_keyName != NULL)
    {
        char *keyNameChars= (char *)(env)->GetStringUTFChars(j_keyName, NULL);
        strcpy(keyname,keyNameChars);
        env->ReleaseStringUTFChars(j_keyName, (const char *)keyNameChars);
        keyNameChars = NULL;
    }
    else
    {
        GetKeyName(keyVersion,keyname);
    }

    PK11SymKey *masterKey = NULL;

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0 ||
        (keyVersion[0] == -1  && strstr(keyname, "#FF") ))
    {
        /* default development keyset */
        status = EncryptData(kek_buffer, cc, cc_len, out);
    }
    else
    {
        if (slot!=NULL)
        {
            masterKey = ReturnSymKey( slot,keyname);

            /* We need to use internal so that the key
             * can be exported  by using PK11_GetKeyData()
             */
            if (masterKey != NULL)
            {
                PK11SymKey *kekKey = ComputeCardKeyOnToken(masterKey,kekData);
                if (kekKey != NULL)
                {
                    Buffer input = Buffer((BYTE*)cc, cc_len);
                    status = EncryptDataWithCardKey(kekKey, input, out);

                    if (kekKey != NULL)
                    {
                        PK11_FreeSymKey( kekKey);
                        kekKey = NULL;
                    }
                }
            }
        }
    }

    if (masterKey != NULL)
    {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if( slot!= NULL )
    {
        PK11_FreeSlot( slot );
        slot = NULL;
    }

    jbyteArray handleBA=NULL;
    if (status != PR_FAILURE && (out.size()>0) )
    {
        jbyte *handleBytes=NULL;
        handleBA = (env)->NewByteArray( out.size());
        handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
        BYTE* outp = (BYTE*)out;
        memcpy(handleBytes, outp,out.size());
        env->ReleaseByteArrayElements( handleBA, handleBytes, 0);
        handleBytes=NULL;
    }

    env->ReleaseByteArrayElements(j_in, cc, JNI_ABORT);
    env->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    env->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);

    return handleBA;
}
