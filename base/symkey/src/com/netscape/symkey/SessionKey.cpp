
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

// AC: KDF SPEC CHANGE: Include headers for NIST SP800-108 KDF functions.
#include "NistSP800_108KDF.h"


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


/* ToDo: fully support nistSP800 in next ticket
*/
PK11SymKey *DeriveKeySCP02(PK11SymKey *cardKey, const Buffer& sequenceCounter, const Buffer& derivationConstant)
{

    PK11SymKey *key = NULL;
    PK11SymKey *master = NULL;
    unsigned char message[KEYLENGTH] = {0};
    unsigned char derivationData[DES3_LENGTH] = {0};

    PRBool invalid_mechanism = PR_TRUE;
    SECStatus s = SECFailure;
    int len = 0;
    int i = 0;

    SECItem *secParam = NULL;

    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11Context *context = NULL;
     SECItem param = { siBuffer, NULL, 0 };

    unsigned char icv[EIGHT_BYTES] = { 0 };

    if( sequenceCounter == NULL || derivationConstant == NULL || 
        sequenceCounter.size() != 2 || derivationConstant.size() != 2 || 
        cardKey == NULL) {
         PR_fprintf(PR_STDERR,"In DeriveKeySCP02!  Error invalid input data!\n");
         goto done;
    }

    PR_fprintf(PR_STDOUT,"In DeriveKeySCP02! \n");
    PR_fprintf(PR_STDOUT,"In DeriveKeySCP02! seqCounter[0] : %d sequenceCounter [1] : %d \n", sequenceCounter[0], sequenceCounter[1]);
    PR_fprintf(PR_STDOUT,"In DeriveKeySCP02! derivationConstant[0] : %x derivationConstant[1] : %x \n", derivationConstant[0], derivationConstant[1]);

    master = cardKey;

    message[0] = (unsigned char) derivationConstant[0];
    message[1] = (unsigned char) derivationConstant[1];
    message[2] = (unsigned char) sequenceCounter[0];
    message[3] = (unsigned char) sequenceCounter[1];


    //ToDo use the new NSS provided derive mechanisms for this operation
    if(invalid_mechanism == PR_FALSE) {
       // Use derive mechanisms
    } else {

        //Use encryption method
        param.data = (unsigned char *) &icv;
        param.len = 8;
        secParam = PK11_ParamFromIV(CKM_DES3_CBC_PAD, &param);
        context = PK11_CreateContextBySymKey(CKM_DES3_CBC_PAD, CKA_ENCRYPT, master, secParam);
        if(context == NULL) {
            goto done;
        }
         s = PK11_CipherOp(context,&derivationData[0] , &len, EIGHT_BYTES, &message[0], EIGHT_BYTES);

         if (s != SECSuccess) { goto done; }
        
         s = PK11_CipherOp(context, &derivationData[EIGHT_BYTES], &len, EIGHT_BYTES, &message[EIGHT_BYTES], EIGHT_BYTES); 
         if (s != SECSuccess) { goto done; } 

         for(i = 0;i < EIGHT_BYTES ;i++)
         {
             derivationData[i+KEYLENGTH] = derivationData[i];
         }

         key = CreateUnWrappedSymKeyOnToken( slot,  master, &derivationData[0] , DES3_LENGTH, PR_FALSE );

          PR_fprintf(PR_STDOUT,"In DeriveKeySCP02! calculated key: %p  \n", key);
    }

    done:

    memset(derivationData, 0, sizeof derivationData);
    if ( context != NULL) {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }

    if (slot) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    if (secParam) {
        SECITEM_FreeItem(secParam, PR_TRUE);
        secParam = NULL;
    }

    return key;
}

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


//ToDo: Fix this to conform the nistSP800
//=================================================================================
#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ComputeSessionKeySCP02
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKeySCP02
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jstring, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKeySCP02(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray keyInfo, jbyteArray CUID, jbyteArray devKeyArray, jbyteArray sequenceCounter, jbyteArray derivationConstant, jstring useSoftToken_s, jstring keySet, jstring sharedSecretKeyName)
{
    /* hardcode permanent dev key */
    jbyte *dev_key = NULL;
    if (devKeyArray != NULL) {
       dev_key = (jbyte*)(env)->GetByteArrayElements(devKeyArray, NULL);
    } else {
        return NULL;
    }

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

    PK11SymKey *devSymKey = NULL;
    PK11SymKey *symkey16 = NULL;
    PK11SymKey *devKey = NULL;


    BYTE devData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    
    const char *devKeyName = NULL;

    const char *macName = "mac";
    const char *encName = "enc";
    const char *kekName = "kek";

    keyType kType = mac;

    /* Derive vars */

    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    /* Java object return vars */

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    jbyte *    cuidValue = NULL;

    jbyte *sc = NULL;
    int sc_len = 0;

    int dc_len = 0;
    jbyte *dc = NULL;

    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;

    Buffer devBuff( ( BYTE *) dev_key , KEYLENGTH );

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

    if( sequenceCounter != NULL) {
        sc = (jbyte*)(env)->GetByteArrayElements( sequenceCounter, NULL);
        sc_len =  (env)->GetArrayLength(sequenceCounter);
    } 

    if( sc == NULL || sc_len != 2) {
        goto done;
    } 

    if( derivationConstant != NULL) {
        dc = (jbyte*)(env)->GetByteArrayElements( derivationConstant, NULL);
        dc_len = (env)->GetArrayLength( derivationConstant);
    }
 
    if( dc == NULL || dc_len != 2) {
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

    //Get  key type from derivation constant
    switch((unsigned char) dc[1]) {
       case 0x1 :
           kType = mac;
           devKeyName = macName;
       break;

       case 0x82:
           kType = enc;
           devKeyName = encName;
       break;

       case 0x81:
           kType = kek;
           devKeyName = kekName;
       break;

       default:
          kType = mac;
          devKeyName = macName;
      break;
    }

    GetDiversificationData(cuidValue,devData,kType);

    PR_fprintf(PR_STDOUT,"In SessionKey.ComputeSessionKeySCP02! keyName %s keyVersion[0] %d keyVersion[1] %d \n",keyname,(int) keyVersion[0],(int) keyVersion[1]);

    if ( (keyVersion[0] == 0x1 && keyVersion[1]== 0x1 ) ||
        (keyVersion[0] == -1 && keyVersion[1] == 0x1))
     
    {
        /* default manufacturers key */

        devSymKey = ReturnDeveloperSymKey(slot, (char *) devKeyName , keySetString, devBuff);

        if( devSymKey == NULL ) {
            goto done;
        }

        PR_fprintf(PR_STDOUT,"SessionKey.ComputeSessionKeySCP02! sc[0] : %d sc[1] : %d \n", sc[0], sc[1]);
        symkey = DeriveKeySCP02(                       //Util::DeriveKey(
            devSymKey, Buffer((BYTE*)sc, sc_len), Buffer((BYTE*)dc, dc_len));

        if(symkey == NULL) 
        {
            goto done;
        }

        //In the enc key case create the auth as well, we may need it later.

        if(kType == enc) {

            PK11SymKey *authKey = NULL;

            authKey = ReturnDeveloperSymKey(slot, (char *) "auth" , keySetString, devBuff);
     
            if(authKey == NULL)
            {
               goto done;
            }

            PK11_FreeSymKey(authKey);
            authKey = NULL; 

        }

    }else
    {
        PR_fprintf(PR_STDOUT,"SessionKey.ComputeSessionKeySCP02! Attempting with master key. \n");
        masterKey = ReturnSymKey( slot,keyname);
        if(masterKey == NULL)
        {
            goto done;
        }

        devKey =ComputeCardKeyOnToken(masterKey,devData,2);
        if(devKey == NULL)
        {
            goto done;
        }
         
        symkey = DeriveKeySCP02(devKey, Buffer((BYTE*)sc, sc_len), Buffer((BYTE*)dc, dc_len));

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
           
    if( devKey ) {
        PK11_FreeSymKey( devKey);
        devKey = NULL;
    }

    if( devSymKey ) {
        PK11_FreeSymKey( devSymKey );
        devSymKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if( sharedSecretKeyNameChars ) {
        (env)->ReleaseStringUTFChars(sharedSecretKeyName, (const char *)sharedSecretKeyNameChars);
        sharedSecretKeyNameChars = NULL;
    }

    if ( handleBytes != NULL) {
        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    if ( sc != NULL) {
        (env)->ReleaseByteArrayElements(sequenceCounter, sc, JNI_ABORT);
    }

    if ( dc != NULL) {
        (env)->ReleaseByteArrayElements(derivationConstant, dc, JNI_ABORT);
    }

    if( keyVersion != NULL) {
        (env)->ReleaseByteArrayElements(keyInfo, keyVersion, JNI_ABORT);
    }

    if ( cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUID, cuidValue, JNI_ABORT);
    }

    if( dev_key != NULL) {
        (env)->ReleaseByteArrayElements(devKeyArray, dev_key, JNI_ABORT);
    }

    if (wrapStatus != SECFailure ){
        return handleBA;
    }else{
        return NULL;
    }

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
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, jbyteArray, jstring, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUID, jbyteArray KDD, jbyteArray macKeyArray, jstring useSoftToken_s, jstring keySet, jstring sharedSecretKeyName)
{
    /* hardcore permanent mac key */
    jbyte *mac_key = NULL;
    if (macKeyArray != NULL) {
       mac_key = (jbyte*)(env)->GetByteArrayElements(macKeyArray, NULL);
    } else {
        return NULL;
    }

    unsigned char input[KEYLENGTH] = {0};
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

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Mac) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* macKey = NULL;
    PK11SymKey* encKey = NULL;
    PK11SymKey* kekKey = NULL;

    BYTE macData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];


    /* Derive vars */

    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    /* Java object return vars */

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

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


    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    // AC: KDF SPEC CHANGE: Moved this call down. (We don't necessarily need it anymore depending on the KDF we're going to use.)
    //GetDiversificationData(cuidValue,macData,mac);//keytype is mac

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

    PR_fprintf(PR_STDOUT,"In SessionKey.ComputeSessionKey! keyName %s keyVersion[0] %d keyVersion[1] %d \n",keyname,(int) keyVersion[0],(int) keyVersion[1]);

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
        PR_fprintf(PR_STDOUT,"In SessionKey.ComputeSessionKey! Upgraded keyset mode. \n");
        masterKey = ReturnSymKey( slot,keyname);
        if(masterKey == NULL)
        {
            goto done;
        }

        // ---------------------------------
        // AC KDF SPEC CHANGE: Determine which KDF to use.
        //
        // Convert to unsigned types
        BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);
        BYTE requestedKeyVersion_byte = static_cast<BYTE>(keyVersion[0]);
        // if requested key version meets setting value, use NIST SP800-108 KDF
        if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, requestedKeyVersion_byte) == true){

            PR_fprintf(PR_STDOUT,"ComputeSessionKey NistSP800_108KDF code: Using NIST SP800-108 KDF.\n");

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
                PR_fprintf(PR_STDERR, "ComputeSessionKey NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                goto done;
            }

            // call NIST SP800-108 KDF routine
            try{
                NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &encKey, &macKey, &kekKey);
            }catch(std::runtime_error& ex){
                PR_fprintf(PR_STDERR, "ComputeSessionKey NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                goto done;
            }catch(...){
                PR_fprintf(PR_STDERR, "ComputeSessionKey NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                goto done;
            }

        // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
        }else{

            PR_fprintf(PR_STDOUT,"ComputeSessionKey NistSP800_108KDF code: Using original KDF.\n");

            // AC: KDF SPEC CHANGE: Moved this call down from the original location.
            //                      (We don't always need to call it anymore; it depends on the KDF we're going to use.)
            //
            // Note the change from "cuidValue" to "kddValue".
            //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
            GetDiversificationData(kddValue,macData,mac);//keytype is mac

            // AC: Derives the mac key for the token.
            macKey =ComputeCardKeyOnToken(masterKey,macData,1);

        } // endif use original KDF
        // ---------------------------------


        // AC: This computes the GP session key using the card-specific MAC key we previously derived.
        symkey = DeriveKey(macKey, Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    }

    // AC: Moved this check out of the else block so we catch NULL keys in the developer key case
    //     (The call already exists outside the "else" block for ComputeEncSessionKey and ComputeKekKey.)
    if(symkey == NULL)
    {
        goto done;
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
           
    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Mac) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    if( macKey ) {
        PK11_FreeSymKey( macKey);
        macKey = NULL;
    }
    if ( encKey ) {
        PK11_FreeSymKey(encKey);
        encKey = NULL;
    }
    if ( kekKey ) {
        PK11_FreeSymKey(kekKey);
        kekKey = NULL;
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

    // AC BUGFIX:  Check the value of handleBytes (not handleBA) before freeing handleBytes!
    //if ( handleBA != NULL) {
    if ( handleBytes != NULL) {
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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
    }

    if( mac_key != NULL) {
        (env)->ReleaseByteArrayElements(macKeyArray, mac_key, JNI_ABORT);
    }

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    if (wrapStatus != SECFailure ){
        return handleBA;
    }else{
        return NULL;
    }
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
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeEncSessionKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeEncSessionKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUID, jbyteArray KDD, jbyteArray encKeyArray, jstring useSoftToken_s, jstring keySet)
{
    /* hardcoded permanent enc key */
    jbyte *enc_key = NULL;
    if(encKeyArray != NULL ) {
       enc_key  =  (jbyte*)(env)->GetByteArrayElements(encKeyArray, NULL);
    } else {
        return NULL;
    }

    unsigned char input[KEYLENGTH] = {0};
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
    PK11SymKey *symkey16   = NULL;

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Enc) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* macKey = NULL;
    PK11SymKey* encKey = NULL;
    PK11SymKey* kekKey = NULL;

    BYTE encData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];

     /* Derive vars */
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    /* Java object return vars */

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

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


    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    // AC: KDF SPEC CHANGE: Moved this call down. (We don't necessarily need it anymore depending on the KDF we're going to use.)
    //GetDiversificationData(cuidValue,encData,enc);

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

        if(masterKey == NULL) {
            goto done;
        }

        // ---------------------------------
        // AC KDF SPEC CHANGE: Determine which KDF to use.
        //
        // Convert to unsigned types
        BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);
        BYTE requestedKeyVersion_byte = static_cast<BYTE>(keyVersion[0]);
        // if requested key version meets setting value, use NIST SP800-108 KDF
        if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, requestedKeyVersion_byte) == true){

            PR_fprintf(PR_STDOUT,"ComputeEncSessionKey NistSP800_108KDF code: Using NIST SP800-108 KDF.\n");

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
                PR_fprintf(PR_STDERR, "ComputeEncSessionKey NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                goto done;
            }

            // call NIST SP800-108 KDF routine
            try{
                NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &encKey, &macKey, &kekKey);
            }catch(std::runtime_error& ex){
                PR_fprintf(PR_STDERR, "ComputeEncSessionKey NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                goto done;
            }catch(...){
                PR_fprintf(PR_STDERR, "ComputeEncSessionKey NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                goto done;
            }

        // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
        }else{

            PR_fprintf(PR_STDOUT,"ComputeEncSessionKey NistSP800_108KDF code: Using original KDF.\n");

            // AC: KDF SPEC CHANGE: Moved this call down from the original location.
            //                      (We don't always need to call it anymore; it depends on the KDF we're going to use.)
            //
            // Note the change from "cuidValue" to "kddValue".
            //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
            GetDiversificationData(kddValue,encData,enc);

            // AC: Derives the enc key for the token.
            encKey =ComputeCardKeyOnToken(masterKey,encData,1);

        } // endif use original KDF
        // ---------------------------------

        if(encKey == NULL) {
            goto done;
        }

        // AC: This computes the GP session key using the card-specific ENC key we previously derived.
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
   
    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Enc) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    if( macKey ) {
        PK11_FreeSymKey(macKey);
        macKey = NULL;
    }
    if ( encKey) {
        PK11_FreeSymKey( encKey);
        encKey = NULL;
    }
    if ( kekKey ) {
        PK11_FreeSymKey(kekKey);
        kekKey = NULL;
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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
    }

    if( enc_key != NULL) {
        (env)->ReleaseByteArrayElements(encKeyArray, enc_key, JNI_ABORT);
    }

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    if (wrapStatus != SECFailure ){
        return handleBA;
    }else{
        return NULL;
    }
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
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
    JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekKey
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16

// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C" JNIEXPORT jobject JNICALL Java_com_netscape_symkey_SessionKey_ComputeKekKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUID, jbyteArray KDD, jbyteArray kekKeyArray, jstring useSoftToken_s, jstring keySet)
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

    unsigned char input[KEYLENGTH] = {0};
    int i;
    jobject keyObj = NULL;

    jbyte *cc =  NULL;
    jbyte *hc = NULL;
    jbyte *    keyVersion = NULL;
    int keyVersion_len = 0;

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

    char *keyNameChars=NULL;
    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (KEK) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* macKey = NULL;
    PK11SymKey* encKey = NULL;
    PK11SymKey* kekKey = NULL;

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


    /* copy card and host challenge into input buffer */
    for (i = 0; i < 8; i++)
    {
        input[i] = cc[i];
    }
    for (i = 0; i < 8; i++)
    {
        input[8+i] = hc[i];
    }

    // AC: KDF SPEC CHANGE: Moved this call down. (We don't necessarily need it anymore depending on the KDF we're going to use.)
    //GetDiversificationData(cuidValue,kekData,kek);//keytype is kek

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

        // ---------------------------------
        // AC KDF SPEC CHANGE: Determine which KDF to use.
        //
        // Convert to unsigned types
        BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);
        BYTE requestedKeyVersion_byte = static_cast<BYTE>(keyVersion[0]);
        // if requested key version meets setting value, use NIST SP800-108 KDF
        if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, requestedKeyVersion_byte) == true){

            PR_fprintf(PR_STDOUT,"ComputeKekKey NistSP800_108KDF code: Using NIST SP800-108 KDF.\n");

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
                PR_fprintf(PR_STDERR, "ComputeKekKey NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                goto done;
            }

            // call NIST SP800-108 KDF routine
            try{
                NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &encKey, &macKey, &kekKey);
            }catch(std::runtime_error& ex){
                PR_fprintf(PR_STDERR, "ComputeKekKey NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                goto done;
            }catch(...){
                PR_fprintf(PR_STDERR, "ComputeKekKey NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                goto done;
            }

        // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
        }else{

            PR_fprintf(PR_STDOUT,"ComputeKekKey NistSP800_108KDF code: Using original KDF.\n");

            // AC: KDF SPEC CHANGE: Moved this call down from the original location.
            //                      (We don't always need to call it anymore; it depends on the KDF we're going to use.)
            //
            // Note the change from "cuidValue" to "kddValue".
            //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
            GetDiversificationData(kddValue,kekData,kek);//keytype is kek

            // AC: Derives the mac key for the token.
            kekKey =ComputeCardKeyOnToken(masterKey,kekData,1);

        } // endif use original KDF
        // ---------------------------------

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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
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
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
    JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCryptogram
        (JNIEnv *, jclass, jstring, jstring, jbyteArray, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, int, jbyteArray, jstring, jstring);
#ifdef __cplusplus
}
#endif
#define KEYLENGTH 16
// AC: KDF SPEC CHANGE: function signature change - added jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_ComputeCryptogram(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName, jbyteArray card_challenge, jbyteArray host_challenge, jbyteArray keyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUID, jbyteArray KDD, int type, jbyteArray authKeyArray, jstring useSoftToken_s, jstring keySet)
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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

    char *tokenNameChars = NULL;
    char *keyNameChars=NULL;
    PK11SlotInfo *slot = NULL;

    jbyte * session_key = NULL;
    PK11SymKey *symkey     = NULL;
    PK11SymKey *masterKey  = NULL;
    PK11SymKey *authSymKey = NULL;

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Enc/Auth) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* macKey = NULL;
    PK11SymKey* authKey = NULL;
    PK11SymKey* kekKey = NULL;

    BYTE authData[KEYLENGTH];
    char keyname[KEYNAMELENGTH];
    Buffer input_x = Buffer(KEYLENGTH);

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    bool error_computing_result = true;

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

    // AC: KDF SPEC CHANGE: Moved this call down. (We don't necessarily need it anymore depending on the KDF we're going to use.)
    //GetDiversificationData(cuidValue,authData,enc);

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

        // ---------------------------------
        // AC KDF SPEC CHANGE: Determine which KDF to use.
        //
        // Convert to unsigned types
        BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);
        BYTE requestedKeyVersion_byte = static_cast<BYTE>(keyVersion[0]);
        // if requested key version meets setting value, use NIST SP800-108 KDF
        if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, requestedKeyVersion_byte) == true){

            PR_fprintf(PR_STDOUT,"ComputeCryptogram NistSP800_108KDF code: Using NIST SP800-108 KDF.\n");

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
                PR_fprintf(PR_STDERR, "ComputeCryptogram NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                goto done;
            }

            // call NIST SP800-108 KDF routine
            try{
                NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &authKey, &macKey, &kekKey);
            }catch(std::runtime_error& ex){
                PR_fprintf(PR_STDERR, "ComputeCryptogram NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                goto done;
            }catch(...){
                PR_fprintf(PR_STDERR, "ComputeCryptogram NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                goto done;
            }

        // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
        }else{

            PR_fprintf(PR_STDOUT,"ComputeCryptogram NistSP800_108KDF code: Using original KDF.\n");

            // AC: KDF SPEC CHANGE: Moved this call down from the original location.
            //                      (We don't always need to call it anymore; it depends on the KDF we're going to use.)
            //
            // Note the change from "cuidValue" to "kddValue".
            //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
            GetDiversificationData(kddValue,authData,enc);

            // AC: Derives the mac key for the token.
            authKey = ComputeCardKeyOnToken(masterKey,authData,1);

        } // endif use original KDF
        // ---------------------------------

        if (authKey == NULL)
        {
            goto done;
        }

        // AC: This computes the GP session key using the card-specific ENC key we previously derived.
        symkey = DeriveKey(authKey,
            Buffer((BYTE*)hc, hc_len), Buffer((BYTE*)cc, cc_len));

    }

    ComputeMAC(symkey, input_x, icv, output);
    session_key = (jbyte *) (BYTE*)output;

    handleBA = (env)->NewByteArray( EIGHT_BYTES);
    handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
    if( handleBytes ) {
        memcpy(handleBytes, session_key, EIGHT_BYTES);

        // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
        // Set flag that we've successfully copied.
        error_computing_result = false;
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
 
    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF, we build all 3 keys despite only using one of them (Enc/Auth) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    if( macKey ) {
        PK11_FreeSymKey(macKey);
        macKey = NULL;
    }
    if( authKey) {
        PK11_FreeSymKey( authKey);
        authKey = NULL;
    }
    if ( kekKey ) {
        PK11_FreeSymKey(kekKey);
        kekKey = NULL;
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

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
    }

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    if (error_computing_result == false){
        return handleBA;
    }else{
        return NULL;
    }
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

    PR_fprintf(PR_STDOUT,"In SessionKey: ECBencrypt! 16 byte key derived....  \n");

    //Wrap the new 16 bit key with the input symkey.

    wrappedKeyItem.data = (unsigned char *) handleBytes;
    wrappedKeyItem.len  = dlen;

    PR_fprintf(PR_STDOUT,"In SessionKey: ECBencrypt! About to wrap des key with sym key.\n");
    wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, symkey, newdeskey, &wrappedKeyItem);

    if( wrapStatus == SECSuccess) {
       PR_fprintf(PR_STDERR, "ECBencrypt wrapStatus %d wrappedKeySize %d \n", wrapStatus, wrappedKeyItem.len); 

       PR_fprintf(PR_STDOUT," ECBencrypt wrapped data: \n");
         Buffer wrappedDataBuf(wrappedKeyItem.data,wrappedKeyItem.len);
         wrappedDataBuf.dump();


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
 * Class:     com_netscape_cms_servlet_tks_DeriveDESKeyFrom3DesKey
 * Method:    DeriveDESKeyFrom3DesKey 
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL
        Java_com_netscape_symkey_SessionKey_DeriveDESKeyFrom3DesKey
        (JNIEnv*, jclass,jstring ,jobject,jlong);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jobject JNICALL 
Java_com_netscape_symkey_SessionKey_DeriveDESKeyFrom3DesKey
(JNIEnv* env, jclass this2, jstring tokenName, jobject des3Key,jlong alg)
{
    PK11SymKey * des3 = NULL;
    PK11SymKey * des  = NULL;
    PK11SymKey * desFinal = NULL;
    PRStatus  r = PR_FAILURE;
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };
    jobject keyObj = NULL;
    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;

    if( des3Key == NULL) {
        goto loser;
    }

    if(alg != CKM_DES_CBC && alg != CKM_DES_ECB) {
        PR_fprintf(PR_STDOUT,"SessionKey.DeriveDESKeyFrom3DesKey invalid alg!.. \n");
        goto loser;
    }

    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        if ( tokenNameChars && !strcmp(tokenNameChars, "internal")) {
            slot = PK11_GetInternalSlot();
        } else {
            slot = ReturnSlot(tokenNameChars);
        }

        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    } else {
        slot = PK11_GetInternalKeySlot();
    }

    if(slot == NULL) {
        goto loser;
    }

    r = JSS_PK11_getSymKeyPtr(env, des3Key, &des3);

    if (r != PR_SUCCESS) {
        PR_fprintf(PR_STDOUT,"SessionKey: DeriveDESKeyFrom3DesKey Unable to get input session 3des sym key! \n");
        goto loser;
    }

    /* Now create a DES key with the first 8 bytes of the input 3des key */

    // Extract first eight bytes from generated key into another key.
     bitPosition = 0;
     paramsItem.data = (CK_BYTE *) &bitPosition;
     paramsItem.len = sizeof bitPosition;


     des = PK11_Derive(des3, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem,  alg , CKA_DERIVE, 8);
     if (des  == NULL ) {
         goto loser;
     }

     //Make sure we move this to the orig token, in case it got moved by NSS
     //during the derive phase.

     desFinal =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, des);


         /* wrap the sesssion in java object. */
     keyObj = JSS_PK11_wrapSymKey(env, &desFinal, NULL);

loser:

    if ( slot != NULL ) {
       PK11_FreeSlot( slot);
       slot = NULL;
    }

    if ( des != NULL) {
        PK11_FreeSymKey(des);
        des = NULL;
    }
    return keyObj;
}

#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_UnwrapSessionKeyWithSharedSecret
 * Method:    UnwrapSessionKeyWithSharedSecret 
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL
        Java_com_netscape_symkey_SessionKey_
        (JNIEnv*, jclass, jstring, jobject,jbyteArray);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jobject JNICALL
Java_com_netscape_symkey_SessionKey_UnwrapSessionKeyWithSharedSecret
(JNIEnv* env, jclass this2, jstring tokenName, jobject sharedSecretKey,jbyteArray sessionKeyBA)
{
    jobject keyObj = NULL;
    PK11SymKey *sessionKey = NULL;
    PK11SymKey *sharedSecret = NULL;
    PK11SymKey *finalKey = NULL;
    PK11SlotInfo *slot = NULL;
    char *tokenNameChars = NULL;
    PRStatus  r = PR_FAILURE;
    int sessionKeyLen = 0;
    jbyte *sessionKeyBytes = NULL;
    SECItem *SecParam = PK11_ParamFromIV(CKM_DES3_ECB, NULL);
    SECItem wrappedItem = {siBuffer , NULL, 0 };

    PR_fprintf(PR_STDOUT,"In SessionKey.UnwrapSessionKeyWithSharedSecret!\n");

    if( sharedSecretKey == NULL || sessionKeyBA == NULL) {
        goto loser;
    }

    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        if ( tokenNameChars && !strcmp(tokenNameChars, "internal")) {
            slot = PK11_GetInternalSlot();
        } else {
            slot = ReturnSlot(tokenNameChars);
        }

        PR_fprintf(PR_STDOUT,"SessionKey.UnwrapSessionKeyWithSharedSecret  slot %p  name %s tokenName %s  \n",slot, PK11_GetSlotName(slot), PK11_GetTokenName(slot));
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    } else {
        slot = PK11_GetInternalKeySlot();
    }

    if(slot == NULL) {
        goto loser;
    }

    sessionKeyBytes = (jbyte *)(env)->GetByteArrayElements(sessionKeyBA, NULL);
    sessionKeyLen = (env)->GetArrayLength(sessionKeyBA); 

    if(sessionKeyBytes == NULL) {
        goto loser;
    }

    r = JSS_PK11_getSymKeyPtr(env, sharedSecretKey, &sharedSecret);

    if (r != PR_SUCCESS) {
        PR_fprintf(PR_STDOUT,"SessionKey: UnwrapSessionKeyWithSharedSecret Unable to get input shared secret sym key! \n"); 
        goto loser;
    }

    wrappedItem.data = (unsigned char *) sessionKeyBytes;
    wrappedItem.len =  sessionKeyLen;


    sessionKey = PK11_UnwrapSymKey(sharedSecret,
                          CKM_DES3_ECB,SecParam, &wrappedItem,
                          CKM_DES3_ECB,
                          CKA_UNWRAP,
                          16);

    PR_fprintf(PR_STDOUT,"SessionKey: UnwrapSessionKeyWithSharedSecret symKey: %p \n",sessionKey);

    if(sessionKey == NULL) {
         PR_fprintf(PR_STDOUT,"SessionKey:UnwrapSessionKeyWithSharedSecret  Error unwrapping a session key! \n");
         goto loser;
    }

    // Done to be compat with current system. Current TPS does this.
    finalKey = CreateDesKey24Byte(slot, sessionKey);

    if(finalKey == NULL) {
          PR_fprintf(PR_STDOUT,"SessionKey:UnwrapSessionKeyWithSharedSecret Error final unwrapped key! \n");
          goto loser;

    }

     /* wrap the sesssion in java object. */
    keyObj = JSS_PK11_wrapSymKey(env, &finalKey, NULL);

loser:

    if ( slot != NULL ) {
       PK11_FreeSlot( slot);
       slot = NULL;
    }

    if ( sessionKeyBA != NULL) {
        (env)->ReleaseByteArrayElements( sessionKeyBA, sessionKeyBytes, 0);
    }

    if(sessionKey) {
        PK11_FreeSymKey(sessionKey);
        sessionKey = NULL; 
    }

    if (SecParam) {
        SECITEM_FreeItem(SecParam, PR_TRUE);
        SecParam = NULL;
    }


    // Don't free finalKey ptr because wrapping routine takes that out of our hands.

    return keyObj;
}

#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_GetSymKeyByName
 * Method:    GetSymKeyByName
 * Signature: ([B[B[B[B)[B
 */
    JNIEXPORT jobject JNICALL
        Java_com_netscape_symkey_SessionKey_GetSymKeyByName
        (JNIEnv*, jclass, jstring, jstring);
#ifdef __cplusplus
}
#endif
extern "C" JNIEXPORT jobject JNICALL
Java_com_netscape_symkey_SessionKey_GetSymKeyByName
(JNIEnv* env, jclass this2, jstring tokenName, jstring keyName)
{

    jobject keyObj = NULL;
    PK11SymKey *key = NULL;
    char *tokenNameChars = NULL;
    char *keyNameChars = NULL;
    PK11SlotInfo *slot = NULL;

    PR_fprintf(PR_STDOUT,"In SessionKey GetSymKeyByName!\n");

    if (keyName) {
        keyNameChars = (char *)(env)->GetStringUTFChars(keyName,NULL);
    }

    if (tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        if ( tokenNameChars && !strcmp(tokenNameChars, "internal")) {
            slot = PK11_GetInternalSlot();
        } else {
            slot = ReturnSlot(tokenNameChars);
        }

        PR_fprintf(PR_STDOUT,"SessionKey: GetSymKeyByName slot %p  name %s tokenName %s keyName %s \n",slot, PK11_GetSlotName(slot), PK11_GetTokenName(slot),keyNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    } else {
        slot = PK11_GetInternalKeySlot();
    }

    if(slot == NULL)
        goto finish;

    key = ReturnSymKey( slot, keyNameChars);

    PR_fprintf(PR_STDOUT,"SessionKey: GetSymKeyByName returned key %p \n",key);
    if (key == NULL) {
        goto finish;
    }

    /* wrap the symkey in java object. */
    keyObj = JSS_PK11_wrapSymKey(env, &key, NULL);

finish:

    if (keyName) {
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }

    if(slot) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    return keyObj;
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
