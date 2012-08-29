
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
#include "secerr.h"

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
// Function takes wither a symkey OR a keybuffer (for the default keyset case)
// To derive a new key.
PK11SymKey *DeriveKey(PK11SymKey *cardKey, const Buffer& hostChallenge, const Buffer& cardChallenge)
{
    PK11SymKey *key = NULL, *master = NULL;
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    unsigned char derivationData[KEYLENGTH];
#ifdef DES2_WORKAROUND
    unsigned char keyData[DES3_LENGTH];
#else
    unsigned char keyData[KEYLENGTH];
#endif
    int i = 0;
    SECStatus s = SECSuccess;
    int len = 0;;
    static SECItem noParams = { siBuffer, NULL, 0 };

    /* vars for PK11_Derive section */
    SECItem param = { siBuffer, NULL, 0 };
    CK_KEY_DERIVATION_STRING_DATA string;
    PK11SymKey *tmp1  = NULL;
    PK11SymKey *tmp2 = NULL; 
    PRBool invalid_mechanism = PR_FALSE;
    CK_OBJECT_HANDLE keyhandle = 0;

    PR_fprintf(PR_STDOUT,"In DeriveKey! \n");
    master = cardKey;

    if( ! master ) goto done;

    for(i = 0;i < 4;i++)
    {
        derivationData[i] = cardChallenge[i+4];
        derivationData[i+4] = hostChallenge[i];
        derivationData[i+8] = cardChallenge[i];
        derivationData[i+12] = hostChallenge[i+4];
    }

    string.pData = &derivationData[0];
    string.ulLen = EIGHT_BYTES;
    param.data = (unsigned char*)&string;
    param.len = sizeof(string);

    invalid_mechanism = PR_TRUE;

    /* When NSS gets full ability to perform this mechanism in soft token, revisit this code to make sure it works. */
    /*
    tmp1 = PK11_Derive( master , CKM_DES_ECB_ENCRYPT_DATA , &param , CKM_CONCATENATE_BASE_AND_KEY  , CKA_DERIVE, 0);

    if ( tmp1 == NULL) {
       if ( PR_GetError() == SEC_ERROR_NO_TOKEN) 
           invalid_mechanism = PR_TRUE;

       PR_fprintf(PR_STDERR,"DeriveKey: Can't create key, using encrypt and derive method ! error %d \n", PR_GetError());
    } else {
       PR_fprintf(PR_STDOUT,"DeriveKey: Successfully created key using encrypt and derive method! \n");
    }
    */
    if ( invalid_mechanism == PR_FALSE) {

        string.pData = &derivationData[EIGHT_BYTES];
        string.ulLen = EIGHT_BYTES;

        tmp2 = PK11_Derive( master , CKM_DES_ECB_ENCRYPT_DATA , &param , CKM_CONCATENATE_BASE_AND_KEY , CKA_DERIVE , 0);

        if ( tmp2 == NULL) {
           PR_fprintf(PR_STDERR,"DeriveKey: Can't derive key using CONCATENATE method! \n");
           goto done;
        } else {
           PR_fprintf(PR_STDOUT,"DeriveKey: Successfully created key using CONCATENATE method! \n");
        }

        keyhandle = PK11_GetSymKeyHandle(tmp2);

        param.data=(unsigned char *) &keyhandle;
        param.len=sizeof(keyhandle);

        key = PK11_Derive ( tmp1 , CKM_CONCATENATE_BASE_AND_KEY , &param ,CKM_DES3_ECB , CKA_DERIVE , 16);

        if ( key == NULL) {
           PR_fprintf(PR_STDERR,"DeriveKey: Can't create final  derived key! \n");
           goto done;
        } else {
           PR_fprintf(PR_STDOUT,"DeriveKey: Successfully created final derived  key! \n");
        }

    }  else { /* We don't have access to the proper derive mechanism, use primitive mechanisms now */

        context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
                      &noParams);

        if (!context) goto done;

        s = PK11_CipherOp(context, &keyData[0], &len, EIGHT_BYTES, &derivationData[0], EIGHT_BYTES);
        if (s != SECSuccess) goto done;

        s = PK11_CipherOp(context, &keyData[EIGHT_BYTES], &len, 8, &derivationData[EIGHT_BYTES], EIGHT_BYTES);
        if (s != SECSuccess) goto done;

         for(i = 0;i < EIGHT_BYTES ;i++)
         {
             keyData[i+KEYLENGTH] = keyData[i];
         }
         
         key = CreateUnWrappedSymKeyOnToken( slot,  master, &keyData[0] , DES3_LENGTH, PR_FALSE );

         if ( key  == NULL ) {
             PR_fprintf(PR_STDERR,"DeriveKey: CreateUnWrappedSymKey failed! %d \n", PR_GetError());
         } else {
            PR_fprintf(PR_STDOUT,"DeriveKey: CreateUnWrappedSymKey succeeded! \n");
         }
    }

    done:
    memset(keyData, 0, sizeof keyData);
    if ( context != NULL) {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }

    if (slot) {
        PK11_FreeSlot(slot);  
        slot = NULL;
    }
 
    if (tmp1) {
        PK11_FreeSymKey(tmp1);
        tmp1 = NULL;
    }

    if (tmp2) {
        PK11_FreeSymKey(tmp2);
        tmp2 = NULL;
    }

    return key;
}

#ifdef __cplusplus
extern "C"
{
#endif
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeKeyCheck
        (JNIEnv *, jclass, jobject deskeyObj);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_ComputeKeyCheck
(JNIEnv* env, jclass this2, jobject deskeyObj)
{
    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    PK11SymKey *key = NULL;
//    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
    SECStatus s = SECFailure;
    PRStatus  r = PR_FAILURE;
    int lenx = 0;
    static SECItem noParams = { siBuffer, NULL, 0 };

    unsigned char value[EIGHT_BYTES];

    memset(value, 0, sizeof value);

    r = JSS_PK11_getSymKeyPtr(env, deskeyObj, &key);

    if (r != PR_SUCCESS) {
        goto finish;
    }

    if ( ! key ) {
        goto finish;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, key,
        &noParams);
    if (!context) {
        goto finish;
    }

    s = PK11_CipherOp(context, &value[0], &lenx, EIGHT_BYTES, &value[0], EIGHT_BYTES);
    if (s != SECSuccess)
    {
        goto finish;
    }
    handleBA = (env)->NewByteArray(3);
    if(handleBA == NULL ) {
        goto finish;
    }
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    if(handleBytes==NULL) {
        goto finish;
    }
    memcpy(handleBytes, value, 3);

    if( handleBytes != NULL) {
        (env)->ReleaseByteArrayElements(handleBA, handleBytes, 0);
    }

finish:

    if ( context != NULL) {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }

//    if ( slot != NULL) {
//        PK11_FreeSlot(slot);
//        slot = NULL;
//    }

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
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray macKeyArray, jstring useSoftToken_s, jstring keySet, jstring sharedSecretKeyName)
{
    /* hardcore permanent mac key */
    jbyte *mac_key = NULL;
    if (macKeyArray != NULL) {
       mac_key = (jbyte*)(env)->GetByteArrayElements(macKeyArray, NULL);
    } else {
        return NULL;
    }

    char input[KEYLENGTH];
    int i = 0;

    SECItem wrappedKeyItem = { siBuffer, NULL , 0};
    SECItem noParams = { siBuffer, NULL, 0 };
    SECStatus wrapStatus = SECFailure;


    char *keyNameChars=NULL;
    char *tokenNameChars=NULL;
    PK11SlotInfo *slot = NULL;
    PK11SlotInfo *internal = PK11_GetInternalKeySlot();

    PK11SymKey *symkey = NULL;
    PK11SymKey *transportKey = NULL;
    PK11SymKey *masterKey = NULL;

    PK11SymKey *macSymKey = NULL;
    PK11SymKey *symkey16 = NULL;
    PK11SymKey *macKey = NULL;


    BYTE macData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];


    /* Derive vars */

    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    /* Java object return vars */

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    jbyte *    cuidValue = NULL;

    jbyte *cc = NULL;
    int cc_len = 0;

    int hc_len = 0;
    jbyte *hc = NULL;

    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;

    Buffer macBuff( ( BYTE *) mac_key , KEYLENGTH );

    char *keySetStringChars = NULL;
    if( keySet != NULL ) {
       keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString =  keySetStringChars;

    if ( keySetString == NULL ) {
        keySetString = (char *) DEFKEYSET_NAME;
    }

    char *sharedSecretKeyNameChars =  NULL;

    if( sharedSecretKeyName != NULL ) {
        sharedSecretKeyNameChars = (char *) (env)->GetStringUTFChars( sharedSecretKeyName, NULL);
    }

    char *sharedSecretKeyNameString = sharedSecretKeyNameChars;

    if ( sharedSecretKeyNameString == NULL ) {
        sharedSecretKeyNameString = (char *) TRANSPORT_KEY_NAME;
    }

    GetSharedSecretKeyName(sharedSecretKeyNameString);

    if( card_challenge != NULL) {
        cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
        cc_len =  (env)->GetArrayLength(card_challenge);
    } 

    if( cc == NULL) {
        goto done;
    } 

    if( host_challenge != NULL) {
        hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
        hc_len = (env)->GetArrayLength( host_challenge);
    }
 
    if( hc == NULL) {
        goto done;
    }
 
    if( keyInfo != NULL) { 
      keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);

      if( keyVersion) {
          keyVersion_len =  (env)->GetArrayLength(keyInfo);
      }
    }

    if( !keyVersion || (keyVersion_len < 2) ){
        goto done;
    }

    if ( CUID != NULL ) {
        cuidValue =  (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    }

    if( cuidValue == NULL) {
        goto done;
    }

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    GetDiversificationData(cuidValue,macData,mac);//keytype is mac

    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    if(keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strncpy(keyname,keyNameChars,KEYNAMELENGTH);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    PR_fprintf(PR_STDOUT,"In SessionKey.ComputeSessionKey! \n");

    if ( (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 && strcmp( keyname, "#01#01") == 0) ||
        (keyVersion[0] == -1 && strstr(keyname, "#FF")))
     
    {
        /* default manufacturers key */

        macSymKey = ReturnDeveloperSymKey(slot, (char *) "mac" , keySetString, macBuff);

        if( macSymKey == NULL ) {
            goto done;
        }
 
        symkey = DeriveKey(                       //Util::DeriveKey(
            macSymKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    }else
    {
        masterKey = ReturnSymKey( slot,keyname);
        if(masterKey == NULL)
        {
            goto done;
        }

        macKey =ComputeCardKeyOnToken(masterKey,macData);
        if(macKey == NULL)
        {
            goto done;
        }
         
        symkey = DeriveKey(macKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

        if(symkey == NULL)
        {
            goto done;
        }
    }
    //Now wrap the key for the trip back to TPS with shared secret transport key

    symkey16 = NULL;
     transportKey = ReturnSymKey( internal, GetSharedSecretKeyName(NULL));
    if ( transportKey == NULL ) {
        PR_fprintf(PR_STDERR, "Can't find shared secret transport key! \n");
        goto done;
    }

    handleBA = (env)->NewByteArray( KEYLENGTH);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);

    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;

    symkey16 = PK11_Derive(symkey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, 16);
    if ( !symkey16 ) {
        PR_fprintf(PR_STDERR,"Can't derive 16 byte key from 24 byte symkey! \n");
        goto done;
    }

    wrappedKeyItem.data = (unsigned char *) handleBytes;
    wrappedKeyItem.len  =  KEYLENGTH;
    wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, transportKey, symkey16, &wrappedKeyItem);

    if(wrapStatus == SECFailure )
    {
        PR_fprintf(PR_STDERR, "Can't wrap session key! Error: %d \n", PR_GetError());
    }

done:

    if( slot) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    if( internal ) {
        PK11_FreeSlot(internal);
        internal = NULL;
    }

    if ( symkey ) {
        PK11_FreeSymKey( symkey);
        symkey = NULL;
    }

    if ( transportKey )  {
        PK11_FreeSymKey( transportKey );
        transportKey = NULL;
    }

    if ( symkey16 ) {
        PK11_FreeSymKey( symkey16 );
        symkey16 = NULL;
    }

    if( masterKey ) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }
           
    if( macKey ) {
        PK11_FreeSymKey( macKey);
        macKey = NULL;
    }

    if( macSymKey ) {
        PK11_FreeSymKey( macSymKey );
        macSymKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if( sharedSecretKeyNameChars ) {
        (env)->ReleaseStringUTFChars(sharedSecretKeyName, (const char *)sharedSecretKeyNameChars);
        sharedSecretKeyNameChars = NULL;
    }

    if ( handleBA != NULL) {
        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    if ( cc != NULL) {
        (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    }

    if ( hc != NULL) {
        (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);
    }

    if( keyVersion != NULL) {
        (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if ( cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

    if( mac_key != NULL) {
        (env)->ReleaseByteArrayElements(macKeyArray, mac_key, JNI_ABORT);
    }

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
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeEncSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray encKeyArray, jstring useSoftToken_s, jstring keySet)
{
    /* hardcoded permanent enc key */
    jbyte *enc_key = NULL;
    if(encKeyArray != NULL ) {
       enc_key  =  (jbyte*)(env)->GetByteArrayElements(encKeyArray, NULL);
    } else {
        return NULL;
    }

    char input[KEYLENGTH];
    int i = 0;

    SECItem wrappedKeyItem = { siBuffer, NULL , 0};
    SECItem noParams = { siBuffer, NULL, 0 };
    SECStatus wrapStatus = SECFailure;

    char *keyNameChars = NULL;
    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;
    PK11SlotInfo *internal = PK11_GetInternalKeySlot();

    PK11SymKey *symkey = NULL;
    PK11SymKey * transportKey = NULL;
    PK11SymKey *masterKey  = NULL;

    PK11SymKey *encSymKey  = NULL;
    PK11SymKey *encKey     = NULL;
    PK11SymKey *symkey16   = NULL;

    BYTE encData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

     /* Derive vars */
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    /* Java object return vars */

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    jbyte *    cuidValue = NULL;

    jbyte *cc = NULL;
    int cc_len = 0;

    int hc_len = 0;
    jbyte *hc = NULL;

    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;

    Buffer encBuff( ( BYTE *) enc_key , KEYLENGTH );

    char *keySetStringChars = NULL; 

    if( keySet != NULL ) {
       keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString =  keySetStringChars;

    if ( keySetString == NULL ) {
        keySetString = (char *) DEFKEYSET_NAME;
    }

    if( card_challenge != NULL) {
        cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
        cc_len =  (env)->GetArrayLength(card_challenge);
    }

    if( cc == NULL) {
        goto done;
    }

    if( host_challenge != NULL) {
        hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
        hc_len = (env)->GetArrayLength( host_challenge);
    }

    if( hc == NULL) {
        goto done;
    }

    if( keyInfo != NULL) {
        keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);

        if( keyVersion) {
            keyVersion_len = (env)->GetArrayLength(keyInfo);
        }
    }

    if( !keyVersion || (keyVersion_len < 2) ){
        goto done;
    }

    if( CUID != NULL) {
        cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    }

    if( cuidValue == NULL) {
        goto done;
    }

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    GetDiversificationData(cuidValue,encData,enc);

    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    if(keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strncpy(keyname,keyNameChars,KEYNAMELENGTH);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }
    else {
        GetKeyName(keyVersion,keyname);
    }

    if ( (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0) ||
        (keyVersion[0] == -1 && strstr(keyname, "#FF")))
    {
        /* default manufacturers key */

        encSymKey = ReturnDeveloperSymKey(slot, (char *) "auth" , keySetString, encBuff);

        if( encSymKey == NULL ) {
            goto done;
        }

        symkey = DeriveKey(                       //Util::DeriveKey(
                encSymKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    }else
    {
        masterKey = ReturnSymKey( slot,keyname);

        /* We need to use internal so that the key
         * can be exported  by using PK11_GetKeyData()
         */
        if(masterKey == NULL) {
            goto done;
        }

        encKey =ComputeCardKeyOnToken(masterKey,encData);
        if(encKey == NULL) {
            goto done;
        }
        symkey = DeriveKey(encKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));
    }

    if(symkey == NULL) {
        goto done;
    }

    //Now wrap the key for the trip back to TPS with shared secret transport key
    transportKey = ReturnSymKey( internal, GetSharedSecretKeyName(NULL));
    if ( transportKey == NULL ) {
        goto done;
    }

    handleBA = (env)->NewByteArray( KEYLENGTH);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);

    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;

    symkey16 = PK11_Derive(symkey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, KEYLENGTH);

    if ( !symkey16 ) {
        PR_fprintf(PR_STDERR,"SessionKey: ComputeEncSessionKey - Can't derive 16 byte key from 24 byte symkey! \n");
        goto done;
    }

    wrappedKeyItem.data = (unsigned char *) handleBytes;
    wrappedKeyItem.len  =   KEYLENGTH;
    wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, transportKey, symkey16, &wrappedKeyItem);

    if ( wrapStatus == SECFailure ) {
        PR_fprintf(PR_STDERR,"SessionKey: ComputeEncSessionKey - Can't wrap encSessionKey !  Error: %d \n", PR_GetError());
    }

done:

    if ( slot )  {
       PK11_FreeSlot ( slot );
       slot = NULL;
    }

    if ( internal) {
       PK11_FreeSlot( internal);
       internal = NULL;
    }

    if( symkey) {
        PK11_FreeSymKey( symkey);
        symkey = NULL;
    }

    if( transportKey) {
        PK11_FreeSymKey( transportKey );
        transportKey = NULL;
    }

    if( masterKey) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if( symkey16) {
        PK11_FreeSymKey( symkey16);
        symkey16 = NULL;
    }

    if ( encSymKey ) { 
        PK11_FreeSymKey( encSymKey);
        encSymKey = NULL;
    }
   
    if( encKey) {
       PK11_FreeSymKey( encKey);
       encKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if ( handleBytes != NULL ) {
        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    if( cc != NULL ) {
        (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    }

    if( hc != NULL ) {
        (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);
    }
    if(keyVersion != NULL ) {
        (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if(cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

    if( enc_key != NULL) {
        (env)->ReleaseByteArrayElements(encKeyArray, enc_key, JNI_ABORT);
    }

    return handleBA;
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
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16

extern "C" JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, jbyteArray kekKeyArray, jstring useSoftToken_s, jstring keySet)
{
    /* hardcoded permanent kek key */
    jbyte *kek_key = NULL;
    if( kekKeyArray != NULL) {
        kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    } else {
        return NULL;
    }

    Buffer kekBuff( ( BYTE *) kek_key , KEYLENGTH );

    char *keySetStringChars = NULL; 
    if( keySet != NULL ) {
       keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString = keySetStringChars;

    if ( keySetString == NULL ) {
        keySetString = (char *) DEFKEYSET_NAME;
    }

    char input[KEYLENGTH];
    int i;
    jobject keyObj = NULL;

    jbyte *cc =  NULL;
    jbyte *hc = NULL;
    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;
    jbyte *    cuidValue = NULL;

    char *keyNameChars=NULL;
    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;

    PK11SymKey *kekKey = NULL;
    PK11SymKey *masterKey = NULL;

    BYTE kekData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

    if( card_challenge != NULL) {
        cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
    }

    if( cc == NULL) {
        goto done;
    }

    if( host_challenge != NULL) {
        hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
    }

    if( hc == NULL) {
        goto done;
    }

    if( keyInfo != NULL) {
        keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
        if( keyVersion) {
          keyVersion_len =  (env)->GetArrayLength(keyInfo);
      }
    }

    if( !keyVersion || (keyVersion_len < 2) ){
        goto done;
    }

    if( CUID != NULL) {
        cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    }

    if( cuidValue == NULL) {
        goto done;
    }

    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    GetDiversificationData(cuidValue,kekData,kek);//keytype is kek

    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    if (keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    PR_fprintf(PR_STDOUT,"In SessionKey.ComputeKekKey! \n");

    if (( keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0 ) ||
        (keyVersion[0] == -1 && strcmp(keyname, "#FF")))
    {
        /* default manufacturers key */

         kekKey = ReturnDeveloperSymKey(slot, (char *) "kek" , keySetString, kekBuff);

    } else {
        masterKey = ReturnSymKey( slot,keyname);

        if(masterKey == NULL)
        {
            goto done;
        }

        kekKey =ComputeCardKeyOnToken(masterKey,kekData);

    }

    if(kekKey == NULL) {
        goto done;
    }

    keyObj = JSS_PK11_wrapSymKey(env, &kekKey, NULL);

done:

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if(masterKey) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if(kekKey) {
        PK11_FreeSymKey( kekKey);
        kekKey = NULL;
    }

    if(slot) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    if (cc != NULL) {
        (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    }

    if (hc != NULL) {
        (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);
    }

    if( keyVersion != NULL ) {
        (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if (cuidValue != NULL ) {
        (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

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
    static SECItem noParams = { siBuffer, NULL, 0 };
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
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, int, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCryptogram(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyteArray CUID, int type, jbyteArray authKeyArray, jstring useSoftToken_s, jstring keySet)
{
/* hardcore permanent mac key */
    jbyte *auth_key = NULL;
    if( authKeyArray != NULL) {
        auth_key = (jbyte*)(env)->GetByteArrayElements(authKeyArray, NULL);
    } else {
        return NULL;
    }

    Buffer authBuff( ( BYTE *) auth_key , KEYLENGTH );
    Buffer icv = Buffer(EIGHT_BYTES, (BYTE)0);
    Buffer output = Buffer(EIGHT_BYTES, (BYTE)0);

    char *keySetStringChars = NULL; 
    if( keySet != NULL ) {
       keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString = keySetStringChars;

    if ( keySetString == NULL ) {
        keySetString = (char *) DEFKEYSET_NAME;
    }

    char input[KEYLENGTH];
    int i;

    PR_fprintf(PR_STDOUT,"In SessionKey: ComputeCryptogram! \n");
    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    jbyte *cc = NULL;
    jbyte *hc = NULL;
    int cc_len = 0;
    int hc_len = 0;
    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;
    jbyte *    cuidValue = NULL;

    char *tokenNameChars = NULL;
    char *keyNameChars=NULL;
    PK11SlotInfo *slot = NULL;

    jbyte * session_key = NULL;
    PK11SymKey *symkey     = NULL;
    PK11SymKey *masterKey  = NULL;
    PK11SymKey *authKey    = NULL;
    PK11SymKey *authSymKey = NULL;

    BYTE authData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    Buffer input_x = Buffer(KEYLENGTH);

    if( card_challenge != NULL ) {
        cc = (jbyte*)(env)->GetByteArrayElements( card_challenge, NULL);
        cc_len =  (env)->GetArrayLength(card_challenge);
    }

    if( cc == NULL) {
        goto done;
    }

    if( host_challenge != NULL ) {
        hc = (jbyte*)(env)->GetByteArrayElements( host_challenge, NULL);
        hc_len = (env)->GetArrayLength( host_challenge);
    }

    if( hc == NULL) {
        goto done;
    }

    if( keyInfo != NULL) {
        keyVersion = (jbyte*)(env)->GetByteArrayElements( keyInfo, NULL);
        if( keyVersion) {
          keyVersion_len =  (env)->GetArrayLength(keyInfo);
      }
    }

    if( !keyVersion || (keyVersion_len < 2) ){
        goto done;
    }

    if( CUID != NULL) {
        cuidValue = (jbyte*)(env)->GetByteArrayElements( CUID, NULL);
    }

    if( cuidValue == NULL) {
        goto done;
    }

    if (type == 0)                                // compute host cryptogram
    {
        /* copy card and host challenge into input buffer */
        for (i = 0; i < EIGHT_BYTES; i++)
        {
            input[i] = cc[i];
        }
        for (i = 0; i < EIGHT_BYTES; i++)
        {
            input[EIGHT_BYTES +i] = hc[i];
        }
    }                                             // compute card cryptogram
    else if (type == 1)
    {
        for (i = 0; i < EIGHT_BYTES; i++)
        {
            input[i] = hc[i];
        }
        for (i = 0; i < EIGHT_BYTES; i++)
        {
            input[EIGHT_BYTES+i] = cc[i];
        }
    }

    input_x.replace(0, (BYTE*) input, KEYLENGTH); 

    GetDiversificationData(cuidValue,authData,enc);

    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    if (keyName)
    {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
        strcpy(keyname,keyNameChars);
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }else
    GetKeyName(keyVersion,keyname);

    if ( (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 &&strcmp( keyname, "#01#01") == 0 ) ||
        (keyVersion[0] == -1 && strstr(keyname, "#FF")))
    {

        /* default manufacturers key */

        authSymKey = ReturnDeveloperSymKey(slot, (char *) "auth" , keySetString, authBuff);
        if( authSymKey == NULL ) {
            goto done;
        }

        symkey = DeriveKey(                      
            authSymKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));
    }
    else
    {
        masterKey = ReturnSymKey( slot,keyname);
        if (masterKey == NULL)
        {
            goto done;
        }

        authKey = ComputeCardKeyOnToken(masterKey,authData);
        if (authKey == NULL)
        {
            goto done;
        }

        symkey = DeriveKey(authKey,
            Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    }

    ComputeMAC(symkey, input_x, icv, output);
    session_key = (jbyte *) (BYTE*)output;

    handleBA = (env)->NewByteArray( EIGHT_BYTES);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    if( handleBytes ) {
        memcpy(handleBytes, session_key, EIGHT_BYTES);
    }

done:

    if( slot ) {
        PK11_FreeSlot( slot );
        slot = NULL;
    }

    if( symkey ) {
        PK11_FreeSymKey( symkey );
        symkey = NULL;
    }

    if( authSymKey ) {
        PK11_FreeSymKey( authSymKey );
        authSymKey = NULL;
    }
 
    if( authKey) {
        PK11_FreeSymKey( authKey);
        authKey = NULL;
    }

    if( masterKey) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if( handleBytes != NULL) {
        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    if( cc != NULL) {
        (env)->ReleaseByteArrayElements(card_challenge, cc, JNI_ABORT);
    }

    if( hc != NULL) {
        (env)->ReleaseByteArrayElements(host_challenge, hc, JNI_ABORT);
    }

    if( keyVersion != NULL) {
        (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if( cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

    return handleBA;
}


//=================================================================================

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
        (JNIEnv*, jclass, jobject, jobject);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_netscape_symkey_SessionKey_ECBencrypt
(JNIEnv* env, jclass this2, jobject symkeyObj, jobject deskeyObj )
{
    jbyteArray handleBA=NULL;
    jint dlen=KEYLENGTH; // applet only supports 16 bytes
    jbyte *handleBytes=NULL;

    PK11SymKey *symkey = NULL;
    PK11SymKey *deskey = NULL;
    PK11SymKey *newdeskey = NULL;
    PRStatus r = PR_FAILURE;
    static SECItem noParams = { siBuffer, NULL, 0 };
    SECItem wrappedKeyItem   = { siBuffer, NULL, 0 };
    SECStatus wrapStatus = SECFailure;

    /* PK11_Derive vars. */

    SECItem paramsItem = { siBuffer, NULL, 0 };
    CK_ULONG bitPosition = 0;

    PR_fprintf(PR_STDOUT,"In SessionKey: ECBencrypt! \n");

    if( !symkeyObj || !deskeyObj) {
       goto finish;
    }

    r = JSS_PK11_getSymKeyPtr(env, symkeyObj, &symkey);
    if (r != PR_SUCCESS) {
        goto finish;
    }

    r = JSS_PK11_getSymKeyPtr(env, deskeyObj, &deskey);
    if (r != PR_SUCCESS) {
        goto finish;
    }
    // Instead of playing with raw keys, let's derive the 16 byte des2 key from 
    // the 24 byte des2 key.

    bitPosition = 0;
    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;

    newdeskey = PK11_Derive(deskey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, 16);

    if ( ! newdeskey ) {
        goto finish;
    }

    dlen = KEYLENGTH;                                // applet suports only 16 bytes

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

    //Wrap the new 16 bit key with the input symkey.

    wrappedKeyItem.data = (unsigned char *) handleBytes;
    wrappedKeyItem.len  = dlen;
    wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, symkey, newdeskey, &wrappedKeyItem);

    if( wrapStatus == SECSuccess) {
       PR_fprintf(PR_STDERR, "ECBencrypt wrapStatus %d wrappedKeySize %d \n", wrapStatus, wrappedKeyItem.len); 
    } else {
       PR_fprintf(PR_STDERR, "ECBecrypt wrap failed! Error %d \n", PR_GetError());
    }

finish:

    if( handleBytes != NULL) {
        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    if ( newdeskey ) {
         PK11_FreeSymKey( newdeskey );
         newdeskey = NULL;
    }

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
    jobject keyObj = NULL;
    PK11SymKey *okey = NULL;
    PK11SymKey *okeyFirstEight = NULL;
    PK11SymKey *concatKey = NULL;
    PK11SymKey *finalKey = NULL;

    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };
    CK_OBJECT_HANDLE keyhandle = 0;

    PR_fprintf(PR_STDOUT,"In SessionKey GenerateSymkey!\n");
    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        if ( tokenNameChars && !strcmp(tokenNameChars, "internal")) {
            slot = PK11_GetInternalSlot();
        } else {
            slot = ReturnSlot(tokenNameChars);
        }

        PR_fprintf(PR_STDOUT,"SessinKey: GenerateSymkey slot %p  name %s tokenName %s \n",slot, PK11_GetSlotName(slot), PK11_GetTokenName(slot));
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    //Generate original 16 byte DES2  key
    okey = PK11_TokenKeyGen(slot, CKM_DES2_KEY_GEN,0, 0, 0, PR_FALSE, NULL);

    if (okey == NULL) {
        goto finish;
    }

     // Extract first eight bytes from generated key into another key.
     bitPosition = 0;
     paramsItem.data = (CK_BYTE *) &bitPosition;
     paramsItem.len = sizeof bitPosition;

     okeyFirstEight = PK11_Derive(okey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT , CKA_DERIVE, 8);
     if (okeyFirstEight  == NULL ) {
         goto finish;
     }

     //Concatenate 8 byte key to the end of the original key, giving new 24 byte key
     keyhandle = PK11_GetSymKeyHandle(okeyFirstEight);
     paramsItem.data=(unsigned char *) &keyhandle;
     paramsItem.len=sizeof(keyhandle);

     concatKey = PK11_Derive ( okey , CKM_CONCATENATE_BASE_AND_KEY , &paramsItem ,CKM_DES3_ECB , CKA_DERIVE , 0);
     if ( concatKey == NULL ) {
         goto finish;
     }

     //Make sure we move this to the orig token, in case it got moved by NSS
     //during the derive phase.

     finalKey =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, concatKey);

    /* wrap the symkey in java object. This sets symkey to NULL. */
    keyObj = JSS_PK11_wrapSymKey(env, &finalKey, NULL);

finish:
    if ( slot != NULL) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    if ( okey != NULL) {
        PK11_FreeSymKey(okey);
        okey = NULL;
    }

    if ( okeyFirstEight != NULL)  {
        PK11_FreeSymKey(okeyFirstEight);
        okeyFirstEight = NULL;
    }

    if ( concatKey != NULL) {
        PK11_FreeSymKey(concatKey);
        concatKey = NULL;
    }

    if ( finalKey != NULL) {
        PK11_FreeSymKey(finalKey);
        finalKey = NULL;
    }

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

    // ToDo: possibly get rid of whole function, not used
    // For now , no need to get rid of PK11_ImportSymKeyWithFlags call.

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
