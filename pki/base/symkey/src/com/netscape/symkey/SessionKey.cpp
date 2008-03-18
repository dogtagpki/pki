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
#include "seccomon.h"
#include "nspr.h"
#ifdef __cplusplus
#include <jni.h>
#include <assert.h>
#include <string.h>

/*
#include <jss_exceptions.h>
#include <jssutil.h>
*/

}
#endif
#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include <cstdarg>
#include <string>

// DRM_PROTO begins
#define PK11SYMKEY_CLASS_NAME "org/mozilla/jss/pkcs11/PK11SymKey"
#define PK11SYMKEY_CONSTRUCTOR_SIG "([B)V"
#define ALL_SYMKEY_OPS  (CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP)
// DRM_PROTO ends

#include "Buffer.h"
#include "SymKey.h"

#define STEAL_JSS
#ifdef STEAL_JSS
// stealing code from JSS to handle DRM support
/*
 * NativeProxy
 */
#define NATIVE_PROXY_CLASS_NAME  "org/mozilla/jss/util/NativeProxy"
#define NATIVE_PROXY_POINTER_FIELD "mPointer"
#define NATIVE_PROXY_POINTER_SIG "[B"

/*
 * SymKeyProxy
 */
#define SYM_KEY_PROXY_FIELD "keyProxy"
#define SYM_KEY_PROXY_SIG "Lorg/mozilla/jss/pkcs11/SymKeyProxy;"

/***********************************************************************
 **
 ** J S S _ p t r T o B y t e A r r a y
 **
 ** Turn a C pointer into a Java byte array. The byte array can be passed
 ** into a NativeProxy constructor.
 **
 ** Returns a byte array containing the pointer, or NULL if an exception
 ** was thrown.
 */
jbyteArray
JSS_ptrToByteArray(JNIEnv *env, void *ptr)
{
    jbyteArray byteArray;

    /* Construct byte array from the pointer */
    byteArray = (env)->NewByteArray(sizeof(ptr));
    if(byteArray==NULL)
    {
        PR_ASSERT( (env)->ExceptionOccurred() != NULL);
        return NULL;
    }
    (env)->SetByteArrayRegion(byteArray, 0, sizeof(ptr), (jbyte*)&ptr);
    if((env)->ExceptionOccurred() != NULL)
    {
        PR_ASSERT(PR_FALSE);
        return NULL;
    }
    return byteArray;
}


/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p S y m K e y

 * Puts a Symmetric Key into a Java object.
 * (Does NOT perform a cryptographic "wrap" operation.)
 * symKey: will be stored in a Java wrapper.
 * Returns: a new PK11SymKey, or NULL if an exception occurred.
 */
jobject
JSS_PK11_wrapSymKey(JNIEnv *env, PK11SymKey **symKey)
{
//    return JSS_PK11_wrapSymKey(env, symKey, NULL);
// hmmm, looks like I may not need to steal code after all
    return JSS_PK11_wrapSymKey(env, symKey);
}


jobject
JSS_PK11_wrapSymKey(JNIEnv *env, PK11SymKey **symKey, PRFileDesc *debug_fd)
{
    jclass keyClass;
    jmethodID constructor;
    jbyteArray ptrArray;
    jobject Key=NULL;

    if (debug_fd)
        PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey\n");

    PR_ASSERT(env!=NULL && symKey!=NULL && *symKey!=NULL);

    /* find the class */
    keyClass = (env)->FindClass(PK11SYMKEY_CLASS_NAME);
    if (debug_fd)
        PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey called FindClass\n");
    if( keyClass == NULL )
    {
        if (debug_fd)
            PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey FindClass NULL\n");
//        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* find the constructor */
    constructor = (env)->GetMethodID(keyClass,
        "<init>"/*PLAIN_CONSTRUCTOR*/,
        PK11SYMKEY_CONSTRUCTOR_SIG);
    if (debug_fd)
        PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey called GetMethodID\n");
    if(constructor == NULL)
    {
//        ASSERT_OUTOFMEM(env);
        if (debug_fd)
            PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey GetMethodID returns NULL\n");
        goto finish;
    }

    /* convert the pointer to a byte array */
    ptrArray = JSS_ptrToByteArray(env, (void*)*symKey);
    if (debug_fd)
        PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey called JSS_ptrToByteArray\n");
    if( ptrArray == NULL )
    {
        if (debug_fd)
            PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey JSS_ptrToByteArray returns NULL\n");
        goto finish;
    }

    /* call the constructor */
    Key = (env)->NewObject( keyClass, constructor, ptrArray);
    if (debug_fd)
        PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey called NewObject\n");

finish:
    if(Key == NULL)
    {
        if (debug_fd)
            PR_fprintf(debug_fd, "DRMproto in JSS_PK11_wrapSymKey NewObject returns NULL\n");
        PK11_FreeSymKey(*symKey);
    }
    *symKey = NULL;
    return Key;
}


/***********************************************************************
 **
 ** J S S _ g e t P t r F r o m P r o x y
 **
 ** Given a NativeProxy, extract the pointer and store it at the given
 ** address.
 **
 ** nativeProxy: a JNI reference to a NativeProxy.
 ** ptr: address of a void* that will receive the pointer extracted from
 **      the NativeProxy.
 ** Returns: PR_SUCCESS on success, PR_FAILURE if an exception was thrown.
 **
 ** Example:
 **  DataStructure *recovered;
 **  jobject proxy;
 **  JNIEnv *env;
 **  [...]
 **  if(JSS_getPtrFromProxy(env, proxy, (void**)&recovered) != PR_SUCCESS) {
 **      return;  // exception was thrown!
 **  }
 */
PRStatus
JSS_getPtrFromProxy(JNIEnv *env, jobject nativeProxy, void **ptr)
{
#ifdef DEBUG
    jclass nativeProxyClass;
#endif
    jclass proxyClass;
    jfieldID byteArrayField;
    jbyteArray byteArray;
    int size;

    PR_ASSERT(env!=NULL && nativeProxy != NULL && ptr != NULL);
    if( nativeProxy == NULL )
    {
//        JSS_throw(env, NULL_POINTER_EXCEPTION);
        return PR_FAILURE;
    }

    proxyClass = (env)->GetObjectClass(nativeProxy);
    PR_ASSERT(proxyClass != NULL);

#ifdef DEBUG
    nativeProxyClass = (env)->FindClass(
        NATIVE_PROXY_CLASS_NAME);
    if(nativeProxyClass == NULL)
    {
//        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    /* make sure what we got was really a NativeProxy object */
    PR_ASSERT( (env)->IsInstanceOf(nativeProxy, nativeProxyClass) );
#endif

    byteArrayField = (env)->GetFieldID(
        proxyClass,
        NATIVE_PROXY_POINTER_FIELD,
        NATIVE_PROXY_POINTER_SIG);
    if(byteArrayField==NULL)
    {
//        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    byteArray = (jbyteArray) (env)->GetObjectField(nativeProxy,
        byteArrayField);
    PR_ASSERT(byteArray != NULL);

    size = sizeof(*ptr);
    PR_ASSERT((env)->GetArrayLength( byteArray) == size);
    (env)->GetByteArrayRegion(byteArray, 0, size, (jbyte*)ptr);
    if( (env)->ExceptionOccurred() )
    {
        PR_ASSERT(PR_FALSE);
        return PR_FAILURE;
    }
    else
    {
        return PR_SUCCESS;
    }
}


/***********************************************************************
 **
 ** J S S _ g e t P t r F r o m P r o x y O w n e r
 **
 ** Given an object which contains a NativeProxy, extract the pointer
 ** from the NativeProxy and store it at the given address.
 **
 ** proxyOwner: an object which contains a NativeProxy member.
 ** proxyFieldName: the name of the NativeProxy member.
 ** proxyFieldSig: the signature of the NativeProxy member.
 ** ptr: address of a void* that will receive the extract pointer.
 ** Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
 **
 ** Example:
 ** <Java>
 ** public class Owner {
 **      protected MyProxy myProxy;
 **      [...]
 ** }
 **
 ** <C>
 **  DataStructure *recovered;
 **  jobject owner;
 **  JNIEnv *env;
 **  [...]
 **  if(JSS_getPtrFromProxyOwner(env, owner, "myProxy", (void**)&recovered)
 **              != PR_SUCCESS) {
 **      return;  // exception was thrown!
 **  }
 */
PRStatus
JSS_getPtrFromProxyOwner(JNIEnv *env, jobject proxyOwner, char* proxyFieldName,
char *proxyFieldSig, void **ptr)
{
    jclass ownerClass;
    jfieldID proxyField;
    jobject proxyObject;

    PR_ASSERT(env!=NULL && proxyOwner!=NULL && proxyFieldName!=NULL &&
        ptr!=NULL);

    /*
     * Get proxy object
     */
    ownerClass = (env)->GetObjectClass(proxyOwner);
    proxyField = (env)->GetFieldID(ownerClass, proxyFieldName,
        proxyFieldSig);
    if(proxyField == NULL)
    {
        return PR_FAILURE;
    }
    proxyObject = (env)->GetObjectField(proxyOwner, proxyField);
    PR_ASSERT(proxyObject != NULL);

    /*
     * Get the pointer from the Native Reference object
     */
    return JSS_getPtrFromProxy(env, proxyObject, ptr);
}


/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t S y m K e y P t r
 *
 */
PRStatus
JSS_PK11_getSymKeyPtr(JNIEnv *env, jobject symKeyObject, PK11SymKey **ptr)
{
    PR_ASSERT(env!=NULL && symKeyObject!=NULL);

    /* Get the pointer from the key proxy */
    return JSS_getPtrFromProxyOwner(env, symKeyObject, SYM_KEY_PROXY_FIELD,
        SYM_KEY_PROXY_SIG, (void**)ptr);
}
#endif                                            //STEAL_JSS

PK11SymKey *DeriveKeyWithCardKey(PK11SymKey *cardkey, const Buffer& hostChallenge, const Buffer& cardChallenge)
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

    for(i = 0;i < 4;i++)
    {
        derivationData[i] = cardChallenge[i+4];
        derivationData[i+4] = hostChallenge[i];
        derivationData[i+8] = cardChallenge[i];
        derivationData[i+12] = hostChallenge[i+4];
    }
    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, cardkey,
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
    if (context) PK11_DestroyContext(context, PR_TRUE);
    if (slot) PK11_FreeSlot(slot);
    if (master) PK11_FreeSymKey(master);

    return key;
}


PK11SymKey *DeriveKey(const Buffer& permKey, const Buffer& hostChallenge, const Buffer& cardChallenge)
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

    /* convert 16-byte to 24-byte triple-DES key */
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
    if (context) PK11_DestroyContext(context, PR_TRUE);
    if (slot) PK11_FreeSlot(slot);
    if (master) PK11_FreeSymKey(master);

    return key;
}

#ifdef __cplusplus
extern "C"
{
#endif
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeKeyCheck
        (JNIEnv *, jclass, jbyteArray);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_ComputeKeyCheck
(JNIEnv* env, jclass this2, jbyteArray data)
{
    jbyteArray handleBA=NULL;
    jint len;
    jbyte *bytes=NULL;
    jbyte *handleBytes=NULL;

    PK11SymKey *key = NULL;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    SECStatus s = SECFailure;
    int lenx;
    static SECItem noParams = { siBuffer, 0, 0 };
#ifdef DES2_WORKAROUND
    unsigned char keyData[24];
#else
    unsigned char keyData[16];
#endif
    SECItem keyItem = {siBuffer, keyData, sizeof(keyData) };
    unsigned char value[8];

    len = (env)->GetArrayLength(data);
    bytes = (env)->GetByteArrayElements(data, NULL);
    if( bytes == NULL )
    {
        goto finish;
    }

/* convert 16-byte to 24-byte triple-DES key */
    memcpy(keyData, bytes, 16);
#ifdef DES2_WORKAROUND
    memcpy(keyData+16, bytes, 8);
#endif
    memset(value, 0, sizeof value);

    key = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
        PK11_OriginGenerated, CKA_ENCRYPT, &keyItem,
        CKF_ENCRYPT, PR_FALSE, 0);
    if( ! key )
    {
        goto finish;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, key,
        &noParams);
    if (!context)
    {
        goto finish;
    }
    s = PK11_CipherOp(context, &value[0], &lenx, 8, &value[0], 8);
    if (s != SECSuccess)
    {
        goto finish;
    }
    handleBA = (env)->NewByteArray(3);
    if(handleBA == NULL )
    {
        goto finish;
    }
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    if(handleBytes==NULL)
    {
        goto finish;
    }
    memcpy(handleBytes, value, 3);

    (env)->ReleaseByteArrayElements(handleBA, handleBytes, 0);

    finish:
    if (context) PK11_DestroyContext(context, PR_TRUE);
    if (slot) PK11_FreeSlot(slot);
    if (key) PK11_FreeSymKey(key);

    return handleBA;
}


//=================================================================================
#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeSessionKey
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray macKeyArray, jstring useSoftToken_s)
{
/* hardcore permanent mac key */
    jbyte *mac_key = (jbyte*)(env)->GetByteArrayElements(macKeyArray, NULL);
    char input[16];
    int i;

//char icv[8];
    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    int cc_len =  (env)->GetArrayLength(card_challenge);

    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
                                                  // .size();
    int hc_len = (env)->GetArrayLength( host_challenge);

    jbyte *    keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte *    cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }
    PK11SymKey *symkey = NULL;

    BYTE macData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

    GetDiversificationData(cuidValue,macData,mac);//keytype is mac

    char *tokenNameChars;
    PK11SlotInfo *slot = NULL;
    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    char *keyNameChars=NULL;

    if(keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0)
    {

        /* default manufacturers key */
        symkey = DeriveKey(                       //Util::DeriveKey(
            Buffer((BYTE*)mac_key, KEYLENGTH), Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        if( slot )
            PK11_FreeSlot( slot );

    }else
    {
        PK11SymKey * masterKey = ReturnSymKey( slot,keyname);

        /* We need to use internal so that the key
         * can be exported  by using PK11_GetKeyData()
         */
        if(masterKey == NULL)
        {

            if(slot)
                PK11_FreeSlot(slot);
            return NULL;
        }

        PK11SymKey *macKey =ComputeCardKeyOnToken(masterKey,macData);

        if(macKey == NULL)
        {

            if(slot)
                PK11_FreeSlot(slot);

            PK11_FreeSymKey(masterKey);
            return NULL;
        }

        symkey = DeriveKeyWithCardKey(macKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        if(symkey == NULL)
        {

            if(slot)
                PK11_FreeSlot(slot);

            PK11_FreeSymKey( masterKey);
            PK11_FreeSymKey( macKey);

            return NULL;
        }

        if( slot )
            PK11_FreeSlot( slot );

        PK11_FreeSymKey( masterKey);
        PK11_FreeSymKey( macKey);

    }

    /* status = EncryptData(kek_key, Buffer(cc,cc_len),out); */
    jbyte * session_key = (jbyte *)  (PK11_GetKeyData(symkey)->data);

    if(session_key == NULL)
    {
        PK11_FreeSymKey(symkey);
        return NULL;
    }

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    handleBA = (env)->NewByteArray( KEYLENGTH);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    memcpy(handleBytes, session_key,KEYLENGTH);
    PK11_FreeSymKey( symkey);

    (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);

    (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);

    (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);

    return handleBA;
}


#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeEncSessionKey
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeEncSessionKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeEncSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray encKeyArray, jstring useSoftToken_s)
{
    /* hardcoded permanent enc key */
    jbyte *enc_key = (jbyte*)(env)->GetByteArrayElements(encKeyArray, NULL);
    char input[16];
    int i;
//char icv[8];

    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    int cc_len =  (env)->GetArrayLength(card_challenge);

    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
                                                  // .size();
    int hc_len = (env)->GetArrayLength( host_challenge);

    jbyte *    keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte *    cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }
    PK11SymKey *symkey = NULL;

    BYTE encData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    GetDiversificationData(cuidValue,encData,enc);
    char *tokenNameChars;
    PK11SlotInfo *slot = NULL;
    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    char *keyNameChars=NULL;

    if(keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }
    else
    {
        GetKeyName(keyVersion,keyname);
    }

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&
        strcmp( keyname, "#01#01") == 0)
    {
        /* default manufacturers key */
        symkey = DeriveKey(                       //Util::DeriveKey(
            Buffer((BYTE*)enc_key, KEYLENGTH), Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        if( slot )
            PK11_FreeSlot( slot );
    }else
    {
        PK11SymKey * masterKey = ReturnSymKey( slot,keyname);

        /* We need to use internal so that the key
         * can be exported  by using PK11_GetKeyData()
         */
        if(masterKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);
            return NULL;

        }

        PK11SymKey *encKey =ComputeCardKeyOnToken(masterKey,encData);
        if(encKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);

            PK11_FreeSymKey(masterKey);

            return NULL;
        }

        symkey = DeriveKeyWithCardKey(encKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        PK11_FreeSymKey( masterKey);
        PK11_FreeSymKey( encKey);

        if(slot)
            PK11_FreeSlot(slot);

    }
    /* status = EncryptData(kek_key, Buffer(cc,cc_len),out); */

    if(symkey == NULL)
    {
        return NULL;
    }

    jbyte * session_key = (jbyte *)  (PK11_GetKeyData(symkey)->data);

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    handleBA = (env)->NewByteArray( KEYLENGTH);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    memcpy(handleBytes, session_key,KEYLENGTH);
    PK11_FreeSymKey( symkey);

    (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);

    (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);

    (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);

    return handleBA;
}


#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeKekSessionKey
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekSessionKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray kekKeyArray, jstring useSoftToken_s)
{
    /* hardcoded permanent kek key */
    jbyte *kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    char input[16];
    int i;
//char icv[8];

    PRFileDesc *debug_fd = NULL;

#ifdef DRM_SUPPORT_DEBUG
    debug_fd = PR_Open("/tmp/debug1.cfu",
        PR_RDWR | PR_CREATE_FILE | PR_APPEND,
        400 | 200);
    PR_fprintf(debug_fd,"ComputeKekSessionKey\n");
#endif                                        // DRM_SUPPORT_DEBUG

    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    int cc_len =  (env)->GetArrayLength(card_challenge);

    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
                                                  // .size();
    int hc_len = (env)->GetArrayLength( host_challenge);

    jbyte *    keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte *    cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }
    PK11SymKey *symkey = NULL;

    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    GetDiversificationData(cuidValue,kekData,kek);//keytype is kek
    char *tokenNameChars;
    PK11SlotInfo *slot = NULL;
    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    char *keyNameChars=NULL;
    if (keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    } else { 
        GetKeyName(keyVersion,keyname);
    }

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0)
    {
        /* default manufacturers key */
        symkey = DeriveKey(                       //Util::DeriveKey(
            Buffer((BYTE*)kek_key, KEYLENGTH), Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));
    } else {
        PK11SymKey * masterKey = ReturnSymKey( slot,keyname);

        /* We need to use internal so that the key
         * can be exported  by using PK11_GetKeyData()
         */
        if(masterKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);
            return NULL;
        }

        PK11SymKey *kekKey =ComputeCardKeyOnToken(masterKey,kekData);
        if (kekKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);

            PK11_FreeSymKey(masterKey);
            return NULL;
        }

        symkey = DeriveKeyWithCardKey(kekKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        PK11_FreeSymKey( masterKey);
        PK11_FreeSymKey( kekKey);

        if(slot)
            PK11_FreeSlot(slot);

    }
    /* status = EncryptData(kek_key, Buffer(cc,cc_len),out); */

    if(symkey == NULL)
    {
        return NULL;
    }

    if (debug_fd)
        PR_fprintf(debug_fd,"ComputeKekSessionKey: got kek session key\n");

    jobject keyObj = JSS_PK11_wrapSymKey(env, &symkey, debug_fd);
    if (keyObj == NULL)
    {
        if (debug_fd)
            PR_fprintf(debug_fd,"ComputeKekSessionKey called wrapSymKey, key NULL\n");
    }
    else
    {
        if (debug_fd)
            PR_fprintf(debug_fd,"ComputeKekSessionKey called wrapSymKey, key not NULL\n");
    }
    return keyObj;
}


#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeKekKey
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray kekKeyArray, jstring useSoftToken_s)
{
    /* hardcoded permanent kek key */
    jbyte *kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    char input[16];
    int i;
//char icv[8];
    jobject keyObj = NULL;

    PRFileDesc *debug_fd = NULL;

#ifdef DRM_SUPPORT_DEBUG
    debug_fd = PR_Open("/tmp/debug1.cfu",
        PR_RDWR | PR_CREATE_FILE | PR_APPEND,
        400 | 200);
    PR_fprintf(debug_fd,"ComputeKekKey\n");
#endif                                        // DRM_SUPPORT_DEBUG

    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
    jbyte *    keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte *    cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    PK11SlotInfo *internalSlot = NULL;
    PK11SymKey *masterKey = NULL;
    PK11SymKey *kekKey = NULL;
    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    GetDiversificationData(cuidValue,kekData,kek);//keytype is kek
    char *tokenNameChars;
    PK11SlotInfo *slot = NULL;
    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    char *keyNameChars=NULL;
    if (keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&
        strcmp( keyname, "#01#01") == 0)
    {
        /* default manufacturers key */
        if (debug_fd)
            PR_fprintf(debug_fd,"ComputeKekKey shouldn't get here\n");

        BYTE masterKeyData[24];
        SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData)};

        memcpy(masterKeyData, (char*)kek_key, 16);
        memcpy(masterKeyData+16, (char*)kek_key, 8);
        if (debug_fd)
            PR_fprintf(debug_fd, "ComputeKekKey DRMproto before import\n");
        kekKey = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
            PK11_OriginUnwrap, CKA_ENCRYPT, &masterKeyItem,
            ALL_SYMKEY_OPS    /*CKF_ENCRYPT*/, PR_FALSE, 0);

        if( slot )
            PK11_FreeSlot( slot );

    } else {
        masterKey = ReturnSymKey( slot,keyname);
        /* We need to use internal so that the key
         * can be exported  by using PK11_GetKeyData()
         */
        if(masterKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);
            return NULL;
        }

        kekKey =ComputeCardKeyOnToken(masterKey,kekData);

    }

    if(kekKey == NULL)
    {
        if(slot)
            PK11_FreeSlot(slot);

        if(masterKey)
            PK11_FreeSymKey(masterKey);

        return NULL;
    }
    if (debug_fd)
        PR_fprintf(debug_fd,"ComputeKekKey: got kek key\n");

    keyObj = JSS_PK11_wrapSymKey(env, &kekKey, debug_fd);
    if (keyObj == NULL)
    {
        if (debug_fd)
            PR_fprintf(debug_fd,"ComputeKekKey: keyObj is NULL\n");
    }
    else
    {
        if (debug_fd)
            PR_fprintf(debug_fd,"ComputeKekKey: keyObj is not NULL\n");
    }

    if(masterKey)
        PK11_FreeSymKey( masterKey);

    if(kekKey)
        PK11_FreeSymKey( kekKey);

    if(slot)
        PK11_FreeSlot(slot);

    if(internalSlot)
        PK11_FreeSlot(internalSlot);

    return keyObj;
}


PRStatus ComputeMAC(PK11SymKey *key, Buffer &x_input,
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
    static unsigned char macPad[] =
    {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    BYTE *input = (BYTE *) x_input;
    int inputLen = x_input.size();

    if(key == NULL)
    {
        rv = PR_FAILURE; goto done;
    }

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
    while (inputLen >= 8)
    {
        for(i = 0;i < 8;i++)
        {
            result[i] ^= input[i];
        }

        s = PK11_CipherOp(context, result, &len, sizeof result, result, sizeof result);
        if (s != SECSuccess) { rv = PR_FAILURE; goto done; }
        if (len != sizeof result)                 /* assert? */
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
    if (context)
    {
        PK11_Finalize(context);
        PK11_DestroyContext(context, PR_TRUE);
    }
    memset(result, 0, sizeof result);

    return rv;
}                                                 /* ComputeMAC */


//=================================================================================
#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeCryptogram
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCryptogram
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, int, jbyteArray, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCryptogram(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, int type, jbyteArray authKeyArray, jstring useSoftToken_s)
{
/* hardcore permanent mac key */
    jbyte *auth_key = (jbyte*)(env)->GetByteArrayElements(authKeyArray, NULL);
    char input[16];
    int i;
//char icv[8];
    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    int cc_len =  (env)->GetArrayLength(card_challenge);

    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
                                                  // .size();
    int hc_len = (env)->GetArrayLength( host_challenge);

    jbyte *    keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
    jbyte *    cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);

    if (type == 0)                                // compute host cryptogram
    {
        /* copy card and host challenge into input buffer */
        for (i = 0; i < 8; i++)
        {
            input[i] = cc[i];
        }
        for (i = 0; i < 8; i++)
        {
            input[8+i] = hc[i];
        }
    }                                             // compute card cryptogram
    else if (type == 1)
    {
        for (i = 0; i < 8; i++)
        {
            input[i] = hc[i];
        }
        for (i = 0; i < 8; i++)
        {
            input[8+i] = cc[i];
        }
    }

    PK11SymKey *symkey = NULL;

    BYTE authData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    GetDiversificationData(cuidValue,authData,enc);
    char *tokenNameChars;
    PK11SlotInfo *slot = NULL;
    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    char *keyNameChars=NULL;

    if (keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    if (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&
        strcmp( keyname, "#01#01") == 0)
    {
        /* default manufacturers key */
        symkey = DeriveKey(                       //Util::DeriveKey(
            Buffer((BYTE*)auth_key, KEYLENGTH), Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        if( slot )
            PK11_FreeSlot( slot );
    }
    else
    {
        PK11SymKey * masterKey = ReturnSymKey( slot,keyname);
        if (masterKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);

            return NULL;
        }

        PK11SymKey *authKey = ComputeCardKeyOnToken(masterKey,authData);
        if (authKey == NULL)
        {
            if(slot)
                PK11_FreeSlot(slot);

            PK11_FreeSymKey( masterKey);
            return NULL;
        }

        if(slot)
            PK11_FreeSlot(slot);

        symkey = DeriveKeyWithCardKey(authKey,
            Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        PK11_FreeSymKey( masterKey);
        PK11_FreeSymKey( authKey);
    }

    if(symkey == NULL)
    {
        return NULL;
    }

    Buffer icv = Buffer(8, (BYTE)0);
    Buffer output = Buffer(8, (BYTE)0);
    Buffer input_x = Buffer((BYTE*)input, 16);
    ComputeMAC(symkey, input_x, icv, output);
    jbyte * session_key = (jbyte *) (BYTE*)output;

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    handleBA = (env)->NewByteArray( 8);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    memcpy(handleBytes, session_key,8);
    PK11_FreeSymKey( symkey);
    (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);
    (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);

    return handleBA;
}


//=================================================================================
#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeCardCryptogram
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCardCryptogram
        (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCardCryptogram(JNIEnv * env, jclass this2, jbyteArray auth_key, jbyteArray card_challenge, jbyteArray host_challenge)
{
    char input[16];
    int i;

    jbyte *ak = (jbyte*)(env)->GetByteArrayElements( auth_key, NULL);
    int ak_len =  (env)->GetArrayLength(auth_key);

    jbyte *cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    int cc_len =  (env)->GetArrayLength(card_challenge);

    jbyte *hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
                                                  // .size();
    int hc_len = (env)->GetArrayLength( host_challenge);

    for (i = 0; i < 8; i++)
    {
        input[i] = hc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = cc[i];
    }

    PK11SymKey *symkey = NULL;

    /* default manufacturers key */
    symkey = DeriveKey(                           //Util::DeriveKey(
        Buffer((BYTE*)ak, ak_len), Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    Buffer icv = Buffer(8, (BYTE)0);
    Buffer output = Buffer(8, (BYTE)0);
    Buffer input_x = Buffer((BYTE*)input, 16);
    ComputeMAC(symkey, input_x, icv, output);
    jbyte * session_key = (jbyte *) (BYTE*)output;

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    handleBA = (env)->NewByteArray( 8);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    memcpy(handleBytes, session_key,8);
    PK11_FreeSymKey( symkey);
    (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    (env)->ReleaseByteArrayElements(auth_key, ak, JNI_ABORT);
    (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);

    return handleBA;
}


#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_ECBencrypt
 * Method:    ECBencrypt
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL
        Java_com_netscape_symkey_SessionKey_ECBencrypt
        (JNIEnv*, jclass, jobject, jbyteArray);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_ECBencrypt
(JNIEnv* env, jclass this2, jobject symkeyObj, jbyteArray data)
{
    jbyteArray handleBA=NULL;
    jint datalen, i;
    jint dlen=16; // applet only supports 16 bytes
    jbyte *databytes=NULL;
    jbyte *handleBytes=NULL;

    PK11SymKey *symkey = NULL;
    PK11Context *context = NULL;
    PRStatus r = PR_FAILURE;
    SECStatus s = SECFailure;
    int lenx;
    static SECItem noParams = { siBuffer, 0, 0 };

    unsigned char result[8];
/*
    PRFileDesc *debug_fd = PR_Open("/tmp/debug.cfu",
           PR_RDWR | PR_CREATE_FILE | PR_APPEND,
                   400 | 200);

    PR_fprintf(debug_fd,"ECBencrypt\n");
*/
    r = JSS_PK11_getSymKeyPtr(env, symkeyObj, &symkey);
    if (r != PR_SUCCESS)
    {
        goto finish;
    }

    datalen = (jint)(env)->GetArrayLength(data);
    databytes = (jbyte*)(env)->GetByteArrayElements(data, NULL);
    if( databytes == NULL )
    {
        goto finish;
    }

    if( ! symkey )
    {
        goto finish;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, symkey,
        &noParams);
    if (!context)
    {
        goto finish;
    }

    if (datalen > 16)
        dlen = 16;                                // applet suports only 16 bytes

    handleBA = (env)->NewByteArray(dlen);
    if(handleBA == NULL )
    {
        goto finish;
    }
    handleBytes = (jbyte *)(env)->GetByteArrayElements(handleBA, NULL);

    if(handleBytes==NULL)
    {
        goto finish;
    }

    for (i=0; i< dlen; i+=8)
    {
        s = PK11_CipherOp(context, result, &lenx, 8, (unsigned char *)&databytes[i], 8);
        if (s != SECSuccess)
        {
            goto finish;
        }
        memcpy(handleBytes+i, result, 8);
    }

    (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);

    finish:
    if (context) PK11_DestroyContext(context, PR_TRUE);

    return handleBA;
}


#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_GenerateSymkey
 * Method:    GenerateSymkey
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL
        Java_com_netscape_symkey_SessionKey_GenerateSymkey
        (JNIEnv*, jclass, jstring);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jobject JNICALL
Java_com_netscape_symkey_SessionKey_GenerateSymkey
(JNIEnv* env, jclass this2, jstring tokenName)
{
    jint keylen=24;
    jobject keyObj = NULL;

    PK11SymKey *okey = NULL;
    PK11SymKey *key = NULL;
    char *tokenNameChars;

    PK11SlotInfo *slot = NULL;
    SECStatus s = SECFailure;

    SECItem* okeyItem = NULL;
    unsigned char keyData[24];
    SECItem keyItem = {siBuffer, keyData, sizeof(keyData) };
/*
PRFileDesc *debug_fd = PR_Open("/tmp/debug.cfu",
       PR_RDWR | PR_CREATE_FILE | PR_APPEND,
               400 | 200);

PR_fprintf(debug_fd,"GenerateSymkey\n");
*/
    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    okey = PK11_TokenKeyGen(slot, CKM_DES2_KEY_GEN,0, 0, 0, PR_FALSE, NULL);
    if (okey == NULL)
        goto finish;

    s= PK11_ExtractKeyValue(okey);

    if (s != SECSuccess)
        goto finish;

    okeyItem = PK11_GetKeyData( okey);

    if (okeyItem == NULL)
        goto finish;

    memcpy(keyData, okeyItem->data,  16);

// make the 3rd 8 bytes the same as the 1st
    if (keylen == 24)
    {
        memcpy(keyData+16, okeyItem->data, 8);

        keyItem.len = keylen;
    }

    key = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
        PK11_OriginGenerated, CKA_ENCRYPT, &keyItem,
        CKF_ENCRYPT, PR_FALSE, 0);
    if( ! key )
    {
        goto finish;
    }

    /* wrap the symkey in java object. This sets symkey to NULL. */
    keyObj = JSS_PK11_wrapSymKey(env, &key, NULL);

finish:
    if (slot) PK11_FreeSlot(slot);
    if (okey) PK11_FreeSymKey(okey);
    if (key) PK11_FreeSymKey(key);

    return keyObj;
}


// begin DRM proto

#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    bytes2PK11SymKey
 * Signature:
 */
    JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_bytes2PK11SymKey
        (JNIEnv *, jclass, jbyteArray);
#ifdef __cplusplus
}
#endif

#ifdef DRM_SUPPORT_DEBUG
extern "C" JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_bytes2PK11SymKey(JNIEnv * env, jclass this2, jbyteArray symKeyBytes)
{
    PK11SlotInfo *slot=NULL;
    jobject keyObj = NULL;
    PK11SymKey *symKey=NULL;

// how about do unwrap (decrypt of the symkey in here??

// DRM proto just use internal slot
    slot = PK11_GetInternalKeySlot();

    BYTE masterKeyData[24];
    SECItem masterKeyItem = {siBuffer, masterKeyData, sizeof(masterKeyData)};

    memcpy(masterKeyData, (char*)symKeyBytes, 16);
    memcpy(masterKeyData+16, (char*)symKeyBytes, 8);
    PR_fprintf(debug_fd, "DRMproto before import\n");
    symKey = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
        PK11_OriginUnwrap, CKA_ENCRYPT, &masterKeyItem,
        ALL_SYMKEY_OPS    /*CKF_ENCRYPT*/, PR_FALSE, 0);

    /* wrap the symkey in java object. This sets symkey to NULL. */
    keyObj = JSS_PK11_wrapSymKey(env, &symKey, debug_fd);

finish:
    return keyObj;
}


// end DRM proto
#endif                                            // DRM_SUPPORT_DEBUG
