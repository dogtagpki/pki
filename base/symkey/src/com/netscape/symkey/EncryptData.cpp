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

// AC: KDF SPEC CHANGE: Include headers for NIST SP800-108 KDF functions.
#include "NistSP800_108KDF.h"

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

// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C"  JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_EncryptData
(JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);

// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_EncryptData(JNIEnv * env, jclass this2, jstring j_tokenName, jstring j_keyName, jbyteArray  j_in, jbyteArray keyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUID, jbyteArray KDD, jbyteArray kekKeyArray, jstring useSoftToken_s,jstring keySet)
{
    jbyte * kek_key =  NULL;

    PK11SymKey *masterKey = NULL;

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Kek) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* macKey = NULL;
    PK11SymKey* encKey = NULL;
    PK11SymKey* kekKey = NULL;

    Buffer out = Buffer(KEYLENGTH, (BYTE)0);
    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

    int status = PR_FAILURE;

    jbyte *cc = NULL;
    int cc_len = 0;

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

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


    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    if ( CUID != NULL ) {
        cuidValue =  (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
        cuidValue_len = env->GetArrayLength(CUID);
    }
    if( cuidValue == NULL) {
        goto done;
    }
    if ( cuidValue_len <= 0){  // check that CUID is at least 1 byte in length
        goto done;
    }
    if ( KDD != NULL ){
        kddValue = env->GetByteArrayElements(KDD, NULL);
        kddValue_len = env->GetArrayLength(KDD);
    }
    if ( kddValue == NULL ){
        goto done;
    }
    if ( kddValue_len != static_cast<jsize>(NistSP800_108KDF::KDD_SIZE_BYTES) ){   // check that KDD is expected size
        goto done;
    }


    if( j_in != NULL) {
        cc = (jbyte*)(env)->GetByteArrayElements( j_in, NULL);
        cc_len = (env)->GetArrayLength(j_in);
    }

    if( cc == NULL) {
        goto done;
    }

    // AC: KDF SPEC CHANGE: Moved this call down. (We don't necessarily need it anymore depending on the KDF we're going to use.)
    //GetDiversificationData(cuidValue,kekData,kek);

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

            if (masterKey != NULL)
            {


                // ---------------------------------
                // AC KDF SPEC CHANGE: Determine which KDF to use.
                //
                // Convert to unsigned types
                BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);
                BYTE requestedKeyVersion_byte = static_cast<BYTE>(keyVersion[0]);
                // if requested key version meets setting value, use NIST SP800-108 KDF
                if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, requestedKeyVersion_byte) == true){

                    PR_fprintf(PR_STDOUT,"EncryptData NistSP800_108KDF code: Using NIST SP800-108 KDF.\n");

                    // react to "UseCUIDAsKDD" setting value
                    jbyte* context_jbyte = NULL;
                    jsize context_len_jsize = 0;
                    if (nistSP800_108KdfUseCuidAsKdd == JNI_TRUE){
                        context_jbyte = cuidValue;
                        context_len_jsize = cuidValue_len;
                    }else{
                        context_jbyte = kddValue;
                        context_len_jsize = kddValue_len;
                    }

                    // Converting this way is safe since jbyte is guaranteed to be 8 bits
                    // Of course, this assumes that "char" is 8 bits (not guaranteed, but typical),
                    //            but it looks like this assumption is also made in GetDiversificationData
                    const BYTE* const context = reinterpret_cast<const BYTE*>(context_jbyte);

                    // Convert jsize to size_t
                    const size_t context_len = static_cast<size_t>(context_len_jsize);
                    if (context_len > 0x000000FF){  // sanity check (CUID should never be larger than 255 bytes)
                        PR_fprintf(PR_STDERR, "EncryptData NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                        goto done;
                    }

                    // call NIST SP800-108 KDF routine
                    try{
                        NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &encKey, &macKey, &kekKey);
                    }catch(std::runtime_error& ex){
                        PR_fprintf(PR_STDERR, "EncryptData NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                        PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                        goto done;
                    }catch(...){
                        PR_fprintf(PR_STDERR, "EncryptData NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                        goto done;
                    }

                // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
                }else{

                    PR_fprintf(PR_STDOUT,"EncryptData NistSP800_108KDF code: Using original KDF.\n");

                    // AC: KDF SPEC CHANGE: Moved this call down from the original location.
                    //                      (We don't always need to call it anymore; it depends on the KDF we're going to use.)
                    //
                    // Note the change from "cuidValue" to "kddValue".
                    //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
                    GetDiversificationData(kddValue,kekData,kek);

                    // AC: Derives the Kek key for the token.
                    kekKey = ComputeCardKeyOnToken(masterKey,kekData);

                } // endif use original KDF
                // ---------------------------------


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

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Kek) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    if( macKey ) {
        PK11_FreeSymKey(macKey);
        macKey = NULL;
    }
    if ( encKey ) {
        PK11_FreeSymKey(encKey);
        encKey = NULL;
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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
    }

    return handleBA;
}
