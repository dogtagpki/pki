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

void GetKeyName(jbyte *keyVersion, char *keyname)
{
    int index=0;

    if( !keyname || !keyVersion || 
        (strlen(keyname) < KEYNAMELENGTH)) {
       return;
    }

    if(strlen(masterKeyPrefix)!=0)
    {
        index= strlen(masterKeyPrefix);
        strcpy(keyname,masterKeyPrefix);
    }

    if( (index + 3) >= KEYNAMELENGTH) {
        return;
    }
    
    keyname[index+0]='#';
    sprintf(keyname+index+1,"%.2d", keyVersion[0]);
    keyname[index+3]='#';
    sprintf(keyname+index+4,"%.2d", keyVersion[1]);
}


extern "C"  JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_EncryptData
(JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_EncryptData(JNIEnv * env, jclass this2, jstring j_tokenName, jstring j_keyName, jbyteArray  j_in, jbyteArray keyInfo, jbyteArray CUID, jbyteArray kekKeyArray, jstring useSoftToken_s,jstring keySet)
{
    jbyte * kek_key =  NULL;

    PK11SymKey *masterKey = NULL;
    PK11SymKey *kekKey =  NULL;

    Buffer out = Buffer(KEYLENGTH, (BYTE)0);
    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

    int status = PR_FAILURE;

    jbyte *cc = NULL;
    int cc_len = 0;
    jbyte * cuidValue = NULL;

    if( kekKeyArray != NULL) {
        kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    } else {
        return NULL;
    }

    PK11SlotInfo *slot = NULL;
    PK11SlotInfo *internal = PK11_GetInternalKeySlot();

    Buffer kek_buffer = Buffer((BYTE*)kek_key, KEYLENGTH);
    char *keySetStringChars = NULL;
    if( keySet != NULL) {
        keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString = keySetStringChars;

    if ( keySetString == NULL ) {
        keySetString = (char *) DEFKEYSET_NAME;
    }

    jbyte * keyVersion =  NULL; 
    int keyVersion_len = 0;
    if( keyInfo != NULL) {
        keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
        if( keyVersion) {
            keyVersion_len =  (env)->GetArrayLength(keyInfo);
        }
    }

    if( !keyVersion || (keyVersion_len < 2) ) {
        goto done;
    }

    if( CUID != NULL) {
        cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    }

    if( cuidValue == NULL) {
        goto done;
    }

    if( j_in != NULL) {
        cc = (jbyte*)(env)->GetByteArrayElements( j_in, NULL);
        cc_len = (env)->GetArrayLength(j_in);
    }

    if( cc == NULL) {
        goto done;
    }

    GetDiversificationData(cuidValue,kekData,kek);

    PR_fprintf(PR_STDOUT,"In SessionKey: EncryptData! \n");

    if(j_tokenName != NULL) {
        char *tokenNameChars = (char *)(env)->GetStringUTFChars(j_tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(j_tokenName, (const char *)tokenNameChars);
        tokenNameChars = NULL;
    }

    if(j_keyName != NULL) {
        char *keyNameChars= (char *)(env)->GetStringUTFChars(j_keyName, NULL);
        strcpy(keyname,keyNameChars);
        env->ReleaseStringUTFChars(j_keyName, (const char *)keyNameChars);
        keyNameChars = NULL;
    }
    else {
        GetKeyName(keyVersion,keyname);
    }

    if ( (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 && strcmp( keyname, "#01#01") == 0) ||
        (keyVersion[0] == -1  && strstr(keyname, "#FF") ))
    {
        /* default development keyset */
        Buffer devInput = Buffer((BYTE*)cc, cc_len);
        Buffer empty = Buffer();
        
        kekKey = ReturnDeveloperSymKey( internal, (char *) "kek", keySetString, empty); 

        if ( kekKey ) {
            status = EncryptData(Buffer(),kekKey,devInput, out);
        } else { 
            status = EncryptData(kek_buffer, NULL, devInput, out);
        }
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
                kekKey = ComputeCardKeyOnToken(masterKey,kekData);
                if (kekKey != NULL)
                {
                    Buffer input = Buffer((BYTE*)cc, cc_len);
                    status = EncryptData(Buffer(), kekKey, input, out);
                }
            }
        }
    }

done:

    if (masterKey != NULL) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if( slot != NULL ) {
        PK11_FreeSlot( slot);
        slot = NULL;
    }

    if( internal != NULL) {
       PK11_FreeSlot( internal);
       internal = NULL;
    }

    if ( kekKey != NULL) {
        PK11_FreeSymKey( kekKey);
        kekKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    jbyteArray handleBA=NULL;
    if (status != PR_FAILURE && (out.size()>0) ) {
        jbyte *handleBytes=NULL;
        handleBA = (env)->NewByteArray( out.size());
        handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
        BYTE* outp = (BYTE*)out;
        memcpy(handleBytes, outp,out.size());
        env->ReleaseByteArrayElements( handleBA, handleBytes, 0);
        handleBytes=NULL;
    }

    if( cc != NULL) {
        env->ReleaseByteArrayElements(j_in, cc, JNI_ABORT);
    }

    if( keyVersion != NULL) {
        env->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if( cuidValue != NULL) {
        env->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

    return handleBA;
}
