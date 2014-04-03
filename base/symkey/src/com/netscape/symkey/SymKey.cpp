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

#include <stdio.h>
#include <string.h>

#if defined(WIN32)
#include "fcntl.h"
#include "io.h"
#endif

#if defined(XP_UNIX)
#include <unistd.h>
#include <sys/time.h>
#include <termios.h>
#endif

#if defined(XP_WIN) || defined (XP_PC)
#include <time.h>
#include <conio.h>
#endif

#include "nspr.h"
#include "prtypes.h"
#include "prtime.h"
#include "prlong.h"
#include "pk11func.h"
#include "secasn1.h"
#include "cert.h"
#include "cryptohi.h"
#include "secoid.h"
#include "certdb.h"
#include "nss.h"

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

#include "Buffer.h"
#include "SymKey.h"

typedef unsigned char BYTE;

typedef struct
{
    enum
    {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;

char masterKeyPrefix[PREFIXLENGHT];
char masterKeyNickName[KEYNAMELENGTH];
char masterNewKeyNickName[KEYNAMELENGTH];
char sharedSecretSymKeyName[KEYNAMELENGTH] = { 0 };

//=================================================================================
#ifdef __cplusplus
extern "C"
{
#endif
/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    ListSymmetricKeys
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
    JNIEXPORT jstring JNICALL Java_com_netscape_symkey_SessionKey_ListSymmetricKeys
        (JNIEnv *, jclass, jstring);

#ifdef __cplusplus
}
#endif

PK11SlotInfo *ReturnSlot(char *tokenNameChars)
{
    if( tokenNameChars == NULL)
    {
        return NULL;
    }
    PK11SlotInfo *slot=NULL;

    if(!strcmp( tokenNameChars, "internal" ) || !strcmp( tokenNameChars, "Internal Key Storage Token"))
    {
        slot = PK11_GetInternalKeySlot();
    }
    else
    {
        slot = PK11_FindSlotByName( tokenNameChars );
    }
    return slot;
}


/* Find the Symmetric key with the given nickname
  Returns null if the key could not be found
  Steve wrote this code to replace the old impl */

PK11SymKey * ReturnSymKey( PK11SlotInfo *slot, char *keyname)
{
    char       *name       = NULL;
    PK11SymKey *foundSymKey= NULL;
    PK11SymKey *firstSymKey= NULL;
    PK11SymKey *sk  = NULL;
    PK11SymKey *nextSymKey = NULL;
    secuPWData  pwdata;

    pwdata.source   = secuPWData::PW_NONE;
    pwdata.data     = (char *) NULL;
    if (keyname == NULL)
    {
        goto cleanup;
    }
    if (slot== NULL)
    {
        goto cleanup;
    }
    /* Initialize the symmetric key list. */
    firstSymKey = PK11_ListFixedKeysInSlot( slot , NULL, ( void *) &pwdata );
    /* scan through the symmetric key list for a key matching our nickname */
    sk = firstSymKey;
    while( sk != NULL )
    {
        /* get the nickname of this symkey */
        name = PK11_GetSymKeyNickname( sk );

        /* if the name matches, make a 'copy' of it */
        if ( name != NULL && !strcmp( keyname, name ))
        {
            if (foundSymKey == NULL)
            {
                foundSymKey = PK11_ReferenceSymKey(sk);
            }
            PORT_Free(name);
        }

        sk = PK11_GetNextSymKey( sk );
    }

    /* We're done with the list now, let's free all the keys in it
       It's okay to free our key, because we made a copy of it */

    sk = firstSymKey;
    while( sk != NULL )
    {
        nextSymKey = PK11_GetNextSymKey(sk);
        PK11_FreeSymKey(sk);
        sk = nextSymKey;
    }

    cleanup:
    return foundSymKey;
}

PK11SymKey *CreateDesKey24Byte(PK11SlotInfo *slot, PK11SymKey *origKey) {

    PK11SymKey *newKey = NULL;

    CK_OBJECT_HANDLE keyhandle = 0;
    PK11SymKey *firstEight = NULL;
    PK11SymKey *concatKey = NULL;
    PK11SymKey *internalOrigKey = NULL;
    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };

    PK11SlotInfo *internal = PK11_GetInternalSlot();
    if (  slot == NULL || origKey == NULL || internal == NULL )
        goto loser;

    PR_fprintf(PR_STDOUT,"In SessionKey CreateDesKey24Bit!\n");

    if( internal != slot ) {  //Make sure we do this on the NSS Generic Crypto services because concatanation
        PR_fprintf(PR_STDOUT,"CreateDesKey24Bit! Input key not on internal slot!\n");
        internalOrigKey = PK11_MoveSymKey( internal, CKA_ENCRYPT, 0, PR_FALSE, origKey );
        if(internalOrigKey == NULL) {
            PR_fprintf(PR_STDOUT,"CreateDesKey24Bit! Can't move input key to internal!\n");
            goto loser;
        }
    }

     // Extract first eight bytes from generated key into another key.
    bitPosition = 0;
    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;


    if ( internalOrigKey)
        firstEight = PK11_Derive(internalOrigKey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT , CKA_DERIVE, EIGHT_BYTES);
    else
        firstEight = PK11_Derive(origKey, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT , CKA_DERIVE, EIGHT_BYTES);

    if (firstEight  == NULL ) {
        PR_fprintf(PR_STDOUT,"CreateDesKey24Bit! Can't extract first 8 bits of input key!\n");
        goto loser;
    }

     //Concatenate 8 byte key to the end of the original key, giving new 24 byte key
    keyhandle = PK11_GetSymKeyHandle(firstEight);

    paramsItem.data=(unsigned char *) &keyhandle;
    paramsItem.len=sizeof(keyhandle);

    if ( internalOrigKey ) {
        concatKey = PK11_Derive ( internalOrigKey , CKM_CONCATENATE_BASE_AND_KEY , &paramsItem ,CKM_DES3_ECB , CKA_DERIVE , 0);
    } else {
        concatKey = PK11_Derive ( origKey , CKM_CONCATENATE_BASE_AND_KEY , &paramsItem ,CKM_DES3_ECB , CKA_DERIVE , 0);
    }
        
    if ( concatKey == NULL ) {
         PR_fprintf(PR_STDOUT,"CreateDesKey24Bit: error concatenating 8 bytes on end of key.");
        goto loser;
    }   
        
    //Make sure we move this to the proper token, in case it got moved by NSS
    //during the derive phase.
        
    newKey =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, concatKey);
    
    if ( newKey == NULL ) {
       PR_fprintf(PR_STDOUT,"CreateDesKey24Bit: error moving key to original slot.");
    }   

loser:


    if ( concatKey != NULL ) {
        PK11_FreeSymKey( concatKey );
        concatKey = NULL;
    }

    if ( firstEight != NULL ) {
        PK11_FreeSymKey ( firstEight );
        firstEight = NULL;
    }

    if ( internalOrigKey != NULL ) {
       PK11_FreeSymKey ( internalOrigKey );
       internalOrigKey = NULL;
    }

    //Caller will free the slot input slot object

    if ( internal != NULL ) {
       PK11_FreeSlot( internal);
       internal = NULL;
    }

    return newKey; 
}


extern "C" JNIEXPORT jstring
JNICALL Java_com_netscape_symkey_SessionKey_DeleteKey(JNIEnv * env, jclass this2, jstring tokenName, jstring keyName)

{
    char *tokenNameChars;
    char *keyNameChars;
    int         count        = 0;
    int         keys_deleted = 0;
    PK11SymKey *symKey       = NULL;
    PK11SymKey *nextSymKey   = NULL;
    PK11SlotInfo *slot = NULL;
    SECStatus   rv;
    secuPWData  pwdata;
    pwdata.source   = secuPWData::PW_NONE;
    pwdata.data     = (char *) NULL;
    jstring     retval      = NULL;

    tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
    keyNameChars = (char *)(env)->GetStringUTFChars(keyName, NULL);
    char *result= (char *)malloc(1);

    result[0] = '\0';
    if( tokenNameChars == NULL || keyNameChars==NULL)
    {
        goto finish;
    }
    if(strcmp( tokenNameChars, "internal" ) == 0 )
    {
        slot = PK11_GetInternalKeySlot();
    }
    else if( tokenNameChars != NULL )
    {
        slot = PK11_FindSlotByName( tokenNameChars );
    }
    /* Initialize the symmetric key list. */
    symKey = PK11_ListFixedKeysInSlot( slot , NULL, ( void *) &pwdata );

    /* Iterate through the symmetric key list. */
    while( symKey != NULL )
    {
        char      *name = NULL;
        rv = SECFailure;
        name = PK11_GetSymKeyNickname( symKey );

        if( strcmp( keyNameChars, name ) == 0 )
        {
            rv = PK11_DeleteTokenSymKey( symKey );
        }
        PORT_Free(name);

        if( rv != SECFailure )
        {
            keys_deleted++;
        }

        nextSymKey = PK11_GetNextSymKey( symKey );
        PK11_FreeSymKey( symKey );
        symKey = nextSymKey;

        count++;
    }

    if( keys_deleted == 0 )
    {

        rv = SECFailure;
    }
    else
    {

        rv = SECSuccess;
    }

    finish:
    if (slot)
    {
        PK11_FreeSlot(slot);
    }
    if(tokenNameChars)
    {
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    if(keyNameChars)
    {
        (env)->ReleaseStringUTFChars(keyName, (const char *)keyNameChars);
    }
    retval = (env)->NewStringUTF( result);
    free(result);
    return retval;
}


#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
(x)->pValue=(v); (x)->ulValueLen = (l);

extern "C" JNIEXPORT jstring
JNICALL Java_com_netscape_symkey_SessionKey_ListSymmetricKeys(JNIEnv * env, jclass this2, jstring tokenName)
{
    char *tokenNameChars;
    jstring retval = NULL;
    PK11SymKey *symKey     = NULL;
    PK11SymKey *nextSymKey = NULL;
    secuPWData  pwdata;
    pwdata.source   = secuPWData::PW_NONE;
    pwdata.data     = (char *) NULL;
    PK11SlotInfo *slot = NULL;

    tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
    char *result= (char *)malloc(1);
    result[0] = '\0';
    if( tokenNameChars == NULL )
    {
        goto finish;
    }
    if(strcmp( tokenNameChars, "internal" ) == 0 )
    {
        slot = PK11_GetInternalKeySlot();
    }
    else if( tokenNameChars != NULL )
    {
        slot = PK11_FindSlotByName( tokenNameChars );
    }

    /* Initialize the symmetric key list. */
    symKey = PK11_ListFixedKeysInSlot( slot , NULL, (void *)&pwdata );

    /* Iterate through the symmetric key list. */
    while (symKey != NULL)
    {
        int  count = 0;
        char *name = NULL;
        char *temp = NULL;
        name = PK11_GetSymKeyNickname( symKey );
        temp = result;
        result = (char*)malloc( strlen(name) + strlen(temp) + 2 );
        result[0]='\0';
        strcat(result, temp);
        strcat(result, ",");
        strcat(result, name);
        free(temp);

        PORT_Free(name);

        nextSymKey = PK11_GetNextSymKey( symKey );
        PK11_FreeSymKey( symKey );
        symKey = nextSymKey;

        count++;
    }

    finish:
    if (slot)
    {
        PK11_FreeSlot(slot);
    }
    if(tokenNameChars)
    {
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }
    retval = (env)->NewStringUTF(result);
    free(result);
    return retval;
}


/* DES KEY Parity conversion table. Takes each byte/2 as an index, returns
 * that byte with the proper parity bit set */
static const unsigned char parityTable[256] =
{
/* Even...0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e */
    /* E */   0x01,0x02,0x04,0x07,0x08,0x0b,0x0d,0x0e,
/* Odd....0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e */
    /* O */   0x10,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,
/* Odd....0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e */
    /* O */   0x20,0x23,0x25,0x26,0x29,0x2a,0x2c,0x2f,
/* Even...0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e */
    /* E */   0x31,0x32,0x34,0x37,0x38,0x3b,0x3d,0x3e,
/* Odd....0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e */
    /* O */   0x40,0x43,0x45,0x46,0x49,0x4a,0x4c,0x4f,
/* Even...0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e */
    /* E */   0x51,0x52,0x54,0x57,0x58,0x5b,0x5d,0x5e,
/* Even...0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e */
    /* E */   0x61,0x62,0x64,0x67,0x68,0x6b,0x6d,0x6e,
/* Odd....0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e */
    /* O */   0x70,0x73,0x75,0x76,0x79,0x7a,0x7c,0x7f,
/* Odd....0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e */
    /* O */   0x80,0x83,0x85,0x86,0x89,0x8a,0x8c,0x8f,
/* Even...0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e */
    /* E */   0x91,0x92,0x94,0x97,0x98,0x9b,0x9d,0x9e,
/* Even...0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae */
    /* E */   0xa1,0xa2,0xa4,0xa7,0xa8,0xab,0xad,0xae,
/* Odd....0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe */
    /* O */   0xb0,0xb3,0xb5,0xb6,0xb9,0xba,0xbc,0xbf,
/* Even...0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce */
    /* E */   0xc1,0xc2,0xc4,0xc7,0xc8,0xcb,0xcd,0xce,
/* Odd....0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde */
    /* O */   0xd0,0xd3,0xd5,0xd6,0xd9,0xda,0xdc,0xdf,
/* Odd....0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee */
    /* O */   0xe0,0xe3,0xe5,0xe6,0xe9,0xea,0xec,0xef,
/* Even...0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe */
    /* E */   0xf1,0xf2,0xf4,0xf7,0xf8,0xfb,0xfd,0xfe,
};

void
pk11_FormatDESKey(unsigned char *key, int length)
{
    int i;

    /* format the des key */
    for (i=0; i < length; i++)
    {
        key[i] = parityTable[key[i]>>1];
    }
}


static secuPWData pwdata = { secuPWData::PW_NONE, 0 };

/**
 * Internal token is required when we are doing key diversification
 * where raw key material needs to be accessed
 */
PK11SymKey *ComputeCardKeyOnSoftToken(PK11SymKey *masterKey, unsigned char *data)
{
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11SymKey *key = ComputeCardKey(masterKey, data, slot);
    if( slot != NULL) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    return key;
}

PK11SymKey *ComputeCardKey(PK11SymKey *masterKey, unsigned char *data, PK11SlotInfo *slot)
{
    PK11SymKey *key = NULL;
    PK11Context *context = NULL;
    int keysize = DES3_LENGTH;
    unsigned char *keyData = NULL;
    SECStatus s = SECSuccess;
    int i = 0;
    int len = 0;
    static SECItem noParams = { siBuffer, NULL, 0 };
    unsigned char *in = data;
    PK11SymKey *tmpkey = NULL;
    unsigned char wrappedkey[DES3_LENGTH];
    SECItem wrappeditem = { siBuffer, NULL, 0 };

    keyData = (unsigned char*)malloc(keysize);

    for (i = 0;i < keysize; i++)
    {
        keyData[i] = 0x0;
    }

    if (masterKey == NULL) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: master key is null.\n");
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT,
        masterKey,
        &noParams);

    if (context == NULL) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to create context.\n");
        goto done;
    }

    /* Part 1 */
    s = PK11_CipherOp(context, &keyData[0], &len, 8, in, 8);
    if (s != SECSuccess) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to encrypt #1\n");
        goto done;
    }
    pk11_FormatDESKey(&keyData[0], EIGHT_BYTES); /* set parity */

    /* Part 2 */
    s = PK11_CipherOp(context, &keyData[EIGHT_BYTES], &len, EIGHT_BYTES, in+EIGHT_BYTES, EIGHT_BYTES);
    if (s != SECSuccess) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to encryp #2.\n");
        goto done;
    }
    pk11_FormatDESKey(&keyData[EIGHT_BYTES], EIGHT_BYTES);

    /* Part 3 */
    for(i = 0;i < EIGHT_BYTES;i++)
    {
        keyData[i+KEYLENGTH] = keyData[i];
    }

#define CKF_KEY_OPERATION_FLAGS 0x000e7b00UL

    /* generate a tmp key to import the sym key */
    tmpkey = PK11_TokenKeyGenWithFlags(slot,
        CKM_DES3_KEY_GEN, 0, 0, 0,
        (CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT) & CKF_KEY_OPERATION_FLAGS,
        PR_FALSE, &pwdata);

    if (tmpkey == NULL) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to keygen. \n");
        goto done;
    }
  
    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT,
        tmpkey,
        &noParams);

    if (context == NULL) {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to set context. \n");
        goto done;
    }

    /* encrypt the key with the master key */
    s = PK11_CipherOp(context, wrappedkey, &len, 24, keyData, 24);
    if (s != SECSuccess)
    {
        PR_fprintf(PR_STDERR,"ComputeCardKey: failed to encrypt #3.\n");
        goto done;
    }

    wrappeditem.data = wrappedkey;
    wrappeditem.len = len;

    key = PK11_UnwrapSymKeyWithFlags(tmpkey, CKM_DES3_ECB, &noParams,
        &wrappeditem, CKM_DES3_KEY_GEN, CKA_DECRYPT, 24,
        (CKA_ENCRYPT | CKA_DECRYPT) & CKF_KEY_OPERATION_FLAGS );

done:
    if (keyData != NULL)
    {
        free(keyData);
    }
    if (context != NULL)
    {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }
    if (tmpkey != NULL)
    {
        PK11_FreeSymKey(tmpkey);
        tmpkey = NULL;
    }

    return key;
}

PK11SymKey * ComputeCardKeyOnToken(PK11SymKey *masterKey, BYTE* data)
{
    PK11SlotInfo *slot = PK11_GetSlotFromKey(masterKey);
    PK11SymKey *key = ComputeCardKey(masterKey, data, slot);

    if( slot) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    return key;
}

// Either encrypt data with a provided SymKey OR a key buffer array (for the Default keyset case).
PRStatus EncryptData(const Buffer &kek_key,PK11SymKey *cardKey, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11SymKey *master = NULL;
    PK11SymKey *transportKey = NULL;
    PK11SlotInfo *slot = NULL;
    PK11Context *context = NULL;
    int i = 0;
    SECStatus s = SECFailure;
    int len = 0;
    static SECItem noParams = { siBuffer, NULL, 0 };
#ifdef DES2_WORKAROUND
    unsigned char masterKeyData[DES3_LENGTH];
#else
    unsigned char masterKeyData[KEYLENGTH];
#endif
    unsigned char result[EIGHT_BYTES];

    slot = PK11_GetInternalKeySlot();

    if (slot == NULL) {
        goto done;
    }

    if ( cardKey == NULL ) { /* Developer key set mode.*/
        transportKey = ReturnSymKey( slot, GetSharedSecretKeyName(NULL));

        /* convert 16-byte to 24-byte triple-DES key */
        memcpy(masterKeyData, kek_key, 16);
        memcpy(masterKeyData+16, kek_key, 8);

        master = CreateUnWrappedSymKeyOnToken( slot, transportKey,  masterKeyData, sizeof(masterKeyData), PR_FALSE);

    } else {
        master = cardKey;
    }

    if( master == NULL) {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
        &noParams);

    if (context == NULL) {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += EIGHT_BYTES)
    {
        s = PK11_CipherOp(context, result, &len, EIGHT_BYTES,
            (unsigned char *)(((BYTE*)input)+i), EIGHT_BYTES);

        if (s != SECSuccess) {
            goto done;
        }
        output.replace(i, result, EIGHT_BYTES);
    }

    rv = PR_SUCCESS;

done:

    memset(masterKeyData, 0, sizeof masterKeyData);
    if (context)
    {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }
    if (slot)
    {
        PK11_FreeSlot(slot);
        slot = NULL;
    }
    if (master && cardKey == NULL)
    {
        PK11_FreeSymKey(master);
        master = NULL;
    }

    return rv;
}

PRStatus ComputeKeyCheckWithSymKey(PK11SymKey * newKey, Buffer& output)
{
    PK11SymKey *key = NULL;
    PRStatus status = PR_FAILURE ;
    PK11SlotInfo *slot = NULL;
    PK11Context *context = NULL;
    SECStatus s = SECFailure;
    int len = 0;
    static SECItem noParams = { siBuffer, NULL, 0 };
    unsigned char value[EIGHT_BYTES];

    if ( newKey == NULL ) {
        return status;
    }

    memset(value, 0, sizeof value);

    slot = PK11_GetInternalKeySlot();
    if (slot != NULL)
    {
        key =  newKey ;
        if( key != NULL )
        {
            context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, key,
                &noParams);
            if (context != NULL)
            {
                s = PK11_CipherOp(context, &value[0], &len, 8, &value[0], 8);

                if (s == SECSuccess)
                {
                    output.resize(3);
                    output.replace(0, value, 3);
                    status = PR_SUCCESS;
                }
                PK11_DestroyContext(context, PR_TRUE);
                context = NULL;
            }
            //PK11_FreeSymKey(key);
            //key = NULL;

        }
        if( slot != NULL) {
            PK11_FreeSlot(slot);
            slot = NULL;
        }
    }

    return status;
}

// Create key set data with the help of either a provided old_keyk_ke2_sym key or key buffer (for the Default keyset case).
PRStatus CreateKeySetDataWithSymKeys( Buffer &newMasterVer,const Buffer &old_kek_key2, PK11SymKey *old_kek_key2_sym, PK11SymKey *new_auth_key, PK11SymKey *new_mac_key, PK11SymKey *new_kek_key, Buffer &output)
{
    PRStatus rv = PR_FAILURE;
    static SECItem noParams = { siBuffer, NULL, 0 };
    PK11SymKey *transportKey = NULL;
    PK11SymKey *wrappingKey = NULL;
    BYTE masterKeyData[DES3_LENGTH];

    /* Wrapping vars */
    SECItem wrappedKeyItem   = { siBuffer, NULL , 0 };
    SECStatus wrapStatus = SECFailure;
    PK11SlotInfo *slot = NULL;
    /* Extracting vars */

    CK_ULONG bitPosition = 0;
    SECItem paramsItem = { siBuffer, NULL, 0 };
    paramsItem.data = (CK_BYTE *) &bitPosition;
    paramsItem.len = sizeof bitPosition;

    PK11SymKey *macKey16 = NULL;
    PK11SymKey *authKey16 = NULL;
    PK11SymKey *kekKey16 = NULL;

    Buffer encrypted_auth_key(KEYLENGTH);
    Buffer encrypted_mac_key(KEYLENGTH);
    Buffer encrypted_kek_key(KEYLENGTH);

    Buffer kc_auth_key(3);
    Buffer kc_mac_key(3);
    Buffer kc_kek_key(3);
    Buffer result;

    PR_fprintf(PR_STDOUT,"In CreateKeySetDataWithSymKeys!\n");

    if ( new_auth_key == NULL || new_mac_key == NULL || new_kek_key == NULL) {
        return rv;
    }

    slot = PK11_GetSlotFromKey(new_auth_key);
    if ( old_kek_key2_sym == NULL ) { /* perm key mode */
        /* Find transport key, shared secret */
        transportKey = ReturnSymKey( slot, GetSharedSecretKeyName(NULL));
        if ( transportKey == NULL ) {
            goto done;
        }

        /* convert 16-byte to 24-byte triple-DES key */
        memcpy(masterKeyData, old_kek_key2, KEYLENGTH);
        memcpy(masterKeyData+16, old_kek_key2, EIGHT_BYTES);

        wrappingKey = CreateUnWrappedSymKeyOnToken( slot, transportKey,  masterKeyData, sizeof(masterKeyData), PR_FALSE);

    } else { /* card key mode */
        wrappingKey = old_kek_key2_sym;
    }

        //Now derive 16 byte versions of the provided symkeys
        authKey16 = PK11_Derive(new_auth_key, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, 16);

        if ( authKey16 == NULL ) {
            PR_fprintf(PR_STDERR,"Error deriving authKey16. Error %d \n", PR_GetError());
            goto done;
        }

        wrappedKeyItem.data = (unsigned char *) encrypted_auth_key;
        wrappedKeyItem.len  = encrypted_auth_key.size();
        wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, wrappingKey, authKey16, &wrappedKeyItem);
        if ( wrapStatus == SECFailure ) {
            PR_fprintf(PR_STDERR,"Error wrapping authKey16. Error %d \n", PR_GetError());
            goto done;
        }

         macKey16 = PK11_Derive(new_mac_key, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT, CKA_DERIVE, 16);

        if ( macKey16 == NULL ) {
            PR_fprintf(PR_STDERR,"Error deriving macKey16. Error %d \n", PR_GetError());
            goto done;
        }

        wrappedKeyItem.data = (unsigned char *) encrypted_mac_key;
        wrappedKeyItem.len  = encrypted_mac_key.size();
        wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, wrappingKey, macKey16, &wrappedKeyItem);
        if ( wrapStatus == SECFailure) {
            PR_fprintf(PR_STDERR,"Error wrapping macKey16. Error %d \n", PR_GetError());
            goto done;
        }

         kekKey16 = PK11_Derive(new_kek_key, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, 16);

        if ( kekKey16 == NULL ) {
            goto done;
            PR_fprintf(PR_STDERR,"Error deriving kekKey16. Error %d \n", PR_GetError());
        }

        wrappedKeyItem.data = (unsigned char *) encrypted_kek_key;
        wrappedKeyItem.len  = encrypted_mac_key.size();
        wrapStatus = PK11_WrapSymKey(CKM_DES3_ECB,&noParams, wrappingKey, kekKey16, &wrappedKeyItem);
        if ( wrapStatus == SECFailure) {
            PR_fprintf(PR_STDERR,"Error wrapping kekKey16. Error %d \n", PR_GetError());
            goto done;
        }

        ComputeKeyCheckWithSymKey(new_auth_key, kc_auth_key);

        ComputeKeyCheckWithSymKey(new_mac_key, kc_mac_key);

        ComputeKeyCheckWithSymKey(new_kek_key, kc_kek_key);

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

done:

    if ( kekKey16 != NULL) {
         PK11_FreeSymKey( kekKey16);
         kekKey16 = NULL;
    } 

    if ( authKey16 != NULL) {
         PK11_FreeSymKey( authKey16);
         authKey16 = NULL;
    } 

    if ( macKey16 != NULL) {
         PK11_FreeSymKey( macKey16);
         macKey16 = NULL;
    } 

    if ( slot != NULL ) {
         PK11_FreeSlot( slot);
         slot = NULL;
    }

    if ( transportKey != NULL ) {
        PK11_FreeSymKey( transportKey);
        transportKey = NULL;
    }

    return rv;
}

void GetDiversificationData(jbyte *cuidValue,BYTE *KDC,keyType keytype)
{
    if( ( cuidValue == NULL) || ( KDC == NULL)) {
        return;
    }

    BYTE *lastTwoBytesOfAID     = (BYTE *)cuidValue;
//	BYTE *ICFabricationDate		= (BYTE *)cuidValue + 2;
    BYTE *ICSerialNumber        = (BYTE *)cuidValue + 4;
//	BYTE *ICBatchIdentifier		= (BYTE *)cuidValue + 8;

// Last 2 bytes of AID
    KDC[0]= (BYTE)lastTwoBytesOfAID[0];
    KDC[1]= (BYTE)lastTwoBytesOfAID[1];
    KDC[2]= (BYTE)ICSerialNumber[0];
    KDC[3]= (BYTE)ICSerialNumber[1];
    KDC[4]= (BYTE)ICSerialNumber[2];
    KDC[5]= (BYTE)ICSerialNumber[3];
    KDC[6]= 0xF0;
    KDC[7]= 0x01;
    KDC[8]= (BYTE)lastTwoBytesOfAID[0];
    KDC[9]= (BYTE)lastTwoBytesOfAID[1];
    KDC[10]= (BYTE)ICSerialNumber[0];
    KDC[11]= (BYTE)ICSerialNumber[1];
    KDC[12]= (BYTE)ICSerialNumber[2];
    KDC[13]= (BYTE)ICSerialNumber[3];
    KDC[14]= 0x0F;
    KDC[15]= 0x01;
    if(keytype == enc)
        return;

    KDC[6]= 0xF0;
    KDC[7]= 0x02;
    KDC[14]= 0x0F;
    KDC[15]= 0x02;
    if(keytype == mac)
        return;

    KDC[6]= 0xF0;
    KDC[7]= 0x03;
    KDC[14]= 0x0F;
    KDC[15]= 0x03;
    if(keytype == kek)
        return;

}

static int getMasterKeyVersion(char *newMasterKeyNameChars)
{
    if( newMasterKeyNameChars == NULL || 
        strlen( newMasterKeyNameChars) < 3) {
        return 0;
    }

    char masterKeyVersionNumber[3];
    masterKeyVersionNumber[0]=newMasterKeyNameChars[1];
    masterKeyVersionNumber[1]=newMasterKeyNameChars[2];
    masterKeyVersionNumber[2]=0;
    int newMasterKeyVesion = atoi(masterKeyVersionNumber);
    return newMasterKeyVesion;
}

char *GetSharedSecretKeyName(char *newKeyName) {
    if ( newKeyName && strlen( newKeyName ) > 0 ) {
       if( strlen( sharedSecretSymKeyName) == 0) {
           strncpy( sharedSecretSymKeyName, newKeyName, KEYNAMELENGTH);
       }
    }

    return (char *) sharedSecretSymKeyName ;
}

void getFullName(char * fullMasterKeyName, char * masterKeyNameChars )
{
    if( fullMasterKeyName == NULL || masterKeyNameChars == NULL
        || ( strlen(fullMasterKeyName) + strlen(masterKeyNameChars)) > KEYNAMELENGTH) {
        return;
    }
    fullMasterKeyName[0]='\0';
    if(strlen(masterKeyPrefix)>0)
        strncpy(fullMasterKeyName,masterKeyPrefix, KEYNAMELENGTH);
    strcat(fullMasterKeyName,masterKeyNameChars);
}


/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    DiversifyKey
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)[B
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey
(JNIEnv *, jclass, jstring, jstring, jstring, jstring, jstring, jbyteArray, jbyteArray, jstring, jstring);

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey( JNIEnv * env, jclass this2, jstring tokenName,jstring newTokenName, jstring oldMasterKeyName, jstring newMasterKeyName, jstring keyInfo, jbyteArray CUIDValue, jbyteArray kekKeyArray, jstring useSoftToken_s, jstring keySet)
{
    PK11SymKey *encKey = NULL;
    PK11SymKey *macKey = NULL;
    PK11SymKey *kekKey = NULL;
    Buffer encKeyBuff;
    Buffer macKeyBuff;
    Buffer kekKeyBuff;
    char * oldMasterKeyNameChars=NULL;
    Buffer old_kek_key_buff;
    Buffer newMasterKeyBuffer;
    char fullMasterKeyName[KEYNAMELENGTH];
    char fullNewMasterKeyName[KEYNAMELENGTH];
    PRBool specified_key_is_present = PR_TRUE;
    PK11SymKey *old_kek_sym_key = NULL;

    char *keySetStringChars =  NULL;
    if ( keySet != NULL ) {
        keySetStringChars = (char *) (env)->GetStringUTFChars( keySet, NULL);
    }

    char *keySetString = keySetStringChars;   
 
    if ( keySetString == NULL ) {
        keySetString =  (char *) DEFKEYSET_NAME;
    }

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    int newMasterKeyVesion = 1;

    /* find slot */
    char *tokenNameChars = NULL;
    char * newMasterKeyNameChars = NULL;
    PK11SlotInfo *slot = NULL;
    PK11SlotInfo *internal = PK11_GetInternalKeySlot();

    Buffer output;
    PK11SlotInfo *newSlot =NULL;
    char * newTokenNameChars = NULL;
    char *keyInfoChars = NULL;

    jbyte * cuidValue =  NULL;
    jbyte * old_kek_key = NULL;

    PK11SymKey * masterKey = NULL;
    PK11SymKey * oldMasterKey = NULL;

    BYTE KDCenc[KEYLENGTH];
    BYTE KDCmac[KEYLENGTH];
    BYTE KDCkek[KEYLENGTH];

    if( CUIDValue != NULL) {
        cuidValue = (jbyte*)(env)->GetByteArrayElements( CUIDValue, NULL);
    }

    if( cuidValue == NULL) {
       goto done;
    }

    if( kekKeyArray != NULL) {
        old_kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    }

    if( old_kek_key == NULL) {
        goto done;
    }

    PR_fprintf(PR_STDOUT,"In SessionKey.DiversifyKey! \n");

    GetDiversificationData(cuidValue,KDCenc,enc);
    GetDiversificationData(cuidValue,KDCmac,mac);
    GetDiversificationData(cuidValue,KDCkek,kek);

    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        PR_fprintf(PR_STDOUT,"DiversifyKey: tokenNameChars %s slot %p \n", tokenNameChars,slot);
        if( tokenNameChars != NULL) {
            (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
        }
    }

    if(newMasterKeyName)
    {
        /* newMasterKeyNameChars  #02#01 */
        newMasterKeyNameChars=  (char *)(env)->GetStringUTFChars(newMasterKeyName, NULL);
    }
    /* fullNewMasterKeyName - no prefix #02#01 */
    getFullName(fullNewMasterKeyName,newMasterKeyNameChars);
    PR_fprintf(PR_STDOUT,"DiversifyKey: fullNewMasterKeyName %s . \n", fullNewMasterKeyName);

    if(newTokenName)
    {
        newTokenNameChars = (char *)(env)->GetStringUTFChars(newTokenName, NULL);
        newSlot = ReturnSlot(newTokenNameChars);
        PR_fprintf(PR_STDOUT,"DiversifyKey: newTokenNameChars %s newSlot %p . \n", newTokenNameChars,newSlot);
        if( newTokenNameChars != NULL) {
            (env)->ReleaseStringUTFChars(newTokenName, (const char *)newTokenNameChars);
        }
    }

    masterKey = ReturnSymKey(newSlot,fullNewMasterKeyName);

    if(newMasterKeyNameChars) {
        (env)->ReleaseStringUTFChars(newMasterKeyName, (const char *)newMasterKeyNameChars);
    }

    /* packing return */
    if( keyInfo != NULL) {
         keyInfoChars = (char *)(env)->GetStringUTFChars(keyInfo, NULL);
    }

    newMasterKeyVesion = getMasterKeyVersion(keyInfoChars);

    if(keyInfoChars)
    {
        (env)->ReleaseStringUTFChars(keyInfo, (const char *)keyInfoChars);
    }

    /* NEW MASTER KEY VERSION */
    newMasterKeyBuffer = Buffer((unsigned int) 1,  (BYTE)newMasterKeyVesion);
    if(oldMasterKeyName)
    {
        oldMasterKeyNameChars = (char *)(env)->GetStringUTFChars(oldMasterKeyName, NULL);
        PR_fprintf(PR_STDOUT,"DiversifyKey oldMasterKeyNameChars %s \n", oldMasterKeyNameChars);
    }
    getFullName(fullMasterKeyName,oldMasterKeyNameChars);
    PR_fprintf(PR_STDOUT,"DiversifyKey fullMasterKeyName %s \n", fullMasterKeyName);
    if(newSlot == NULL) {
        newSlot = slot;
    }
    if(strcmp( oldMasterKeyNameChars, "#01#01") == 0 || strcmp( oldMasterKeyNameChars, "#FF#01") == 0)
    {
        old_kek_key_buff    =   Buffer((BYTE*)old_kek_key, KEYLENGTH);
    }else if(strcmp( oldMasterKeyNameChars, "#00#00") == 0)
    {
        /* print Debug message - do not create real keysetdata */
        old_kek_key_buff    =       Buffer((BYTE*)"#00#00", 6);
        output              =       Buffer((BYTE*)old_kek_key, KEYLENGTH);
    }
    else
    {
        oldMasterKey =     ReturnSymKey(slot,fullMasterKeyName);
        old_kek_sym_key = ComputeCardKeyOnToken(oldMasterKey,KDCkek);
        if (oldMasterKey) {
            PK11_FreeSymKey( oldMasterKey );
            oldMasterKey = NULL;
        }
    }
    if(oldMasterKeyNameChars) {
        (env)->ReleaseStringUTFChars(oldMasterKeyName, (const char *)oldMasterKeyNameChars);
    }

    /* special case #01#01 */
    if (fullNewMasterKeyName != NULL && strcmp(fullNewMasterKeyName, "#01#01") == 0)
    {
        Buffer empty = Buffer();

        encKey  = ReturnDeveloperSymKey(internal,(char *) "auth", keySetString, empty);

        if ( encKey == NULL ) {
            goto done; 
        }
        PR_fprintf(PR_STDOUT, "Special case dev key set for DiversifyKey!\n");

        macKey = ReturnDeveloperSymKey(internal, (char *) "mac", keySetString, empty);
        if ( macKey == NULL ) {
            goto done;
        }

        kekKey = ReturnDeveloperSymKey(internal, (char *) "kek", keySetString, empty);

        if ( kekKey == NULL ) {
            goto done;
        }

    } else {
        PR_fprintf(PR_STDOUT,"DiversifyKey: Compute card key on token case ! \n");
        /* compute card key */
        encKey = ComputeCardKeyOnSoftToken(masterKey, KDCenc);
        macKey = ComputeCardKeyOnSoftToken(masterKey, KDCmac);
        kekKey = ComputeCardKeyOnSoftToken(masterKey, KDCkek);

        /* Fixes Bugscape Bug #55855: TKS crashes if specified key
         * is not present -- for each portion of the key, check if
         * the PK11SymKey is NULL before sending it to PK11_GetKeyData()!
         */
        if( encKey == NULL) {
            PR_fprintf(PR_STDERR,"Can't create encKey in DiversifyKey! \n");
            specified_key_is_present = PR_FALSE;
            goto done;
        }
        if( macKey == NULL) {
            PR_fprintf(PR_STDERR,"Can't create macKey in DiversifyKey! \n");
            specified_key_is_present = PR_FALSE;
            goto done;
        }
        if( kekKey == NULL) {
            PR_fprintf(PR_STDERR,"Can't create kekKey in DiversifyKey! \n");
            specified_key_is_present = PR_FALSE;
            goto done;
        }
    }

    if (old_kek_sym_key != NULL) {
        CreateKeySetDataWithSymKeys(newMasterKeyBuffer, Buffer(),
            old_kek_sym_key,
            encKey,
            macKey,
            kekKey,
            output); }
    else {
        old_kek_sym_key =  ReturnDeveloperSymKey(slot, (char *) "kek", keySetString, old_kek_key_buff);
        CreateKeySetDataWithSymKeys(newMasterKeyBuffer, Buffer(),
            old_kek_sym_key,
            encKey,
            macKey,
            kekKey,
            output);
    }

done:
    if (masterKey != NULL) {
        PK11_FreeSymKey( masterKey);
        masterKey = NULL;
    }

    if (encKey != NULL) {
        PK11_FreeSymKey( encKey );
        encKey = NULL;
    }

    if (macKey != NULL) {
        PK11_FreeSymKey( macKey );
        macKey = NULL;
    }

    if (kekKey != NULL) {
        PK11_FreeSymKey( kekKey );
        kekKey = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if( specified_key_is_present )
    {
        if(output.size()>0)
            handleBA = (env)->NewByteArray( output.size());
        else
            handleBA = (env)->NewByteArray(1);
        handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
        memcpy(handleBytes, (BYTE*)output,output.size());

        if( handleBytes != NULL) {
            (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
        }
    }

    if( cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUIDValue, cuidValue, JNI_ABORT);
    }

    if( kekKeyArray != NULL) {
        (env)->ReleaseByteArrayElements(kekKeyArray, old_kek_key, JNI_ABORT);
    }

    if((newSlot != slot) && newSlot) {
        PK11_FreeSlot( newSlot);
        newSlot = NULL;
    }

    if( slot ) {
        PK11_FreeSlot( slot);
        slot = NULL;
    }

    if( internal) {
        PK11_FreeSlot( internal);
        internal = NULL;
    }

    return handleBA;
}

PK11SymKey *CreateUnWrappedSymKeyOnToken( PK11SlotInfo *slot, PK11SymKey * unWrappingKey, BYTE *keyToBeUnWrapped, int sizeOfKeyToBeUnWrapped, PRBool isPerm)
{
    PK11SymKey * unWrappedSymKey = NULL;
    int bufSize = 48;
    unsigned char outbuf[bufSize];
    int final_len = 0;
    SECStatus s = SECSuccess;
    PK11Context * EncContext = NULL;
    SECItem unWrappedKeyItem = { siBuffer, NULL, 0};
    PK11SymKey *unwrapper = NULL;

    PR_fprintf( PR_STDOUT,
        "Creating UnWrappedSymKey on  token. \n");

     if ( (slot == NULL) || (unWrappingKey == NULL) ||
           (keyToBeUnWrapped == NULL) ||
           (sizeOfKeyToBeUnWrapped != DES3_LENGTH)
       )  {
        return NULL;
    }

    PK11SlotInfo *unwrapKeySlot = PK11_GetSlotFromKey( unWrappingKey );

    if ( unwrapKeySlot != slot ) {
        unwrapper =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, unWrappingKey);   
    }

    SECItem *SecParam = PK11_ParamFromIV(CKM_DES3_ECB, NULL);
    if ( SecParam == NULL) {
        goto done;
    }

    EncContext = PK11_CreateContextBySymKey(CKM_DES3_ECB,
                                                CKA_ENCRYPT,
                                                unWrappingKey, SecParam);

    if ( EncContext == NULL) {
        goto done;
    }

    s = PK11_CipherOp(EncContext, outbuf, &final_len, sizeof( outbuf), keyToBeUnWrapped,
                         sizeOfKeyToBeUnWrapped);

    if ( s != SECSuccess) {
        goto done;
    }

    if ( final_len != DES3_LENGTH ) {
        goto done;
    }

    unWrappedKeyItem.data = outbuf;
    unWrappedKeyItem.len  = final_len;


   /* Now try to unwrap our key into the token */
    unWrappedSymKey = PK11_UnwrapSymKeyWithFlagsPerm(unwrapper ? unwrapper : unWrappingKey,
                          CKM_DES3_ECB,SecParam, &unWrappedKeyItem,
                          CKM_DES3_ECB,
                          CKA_UNWRAP,
                          sizeOfKeyToBeUnWrapped, 0, isPerm );
 
done:

    if( SecParam != NULL ) {
        SECITEM_FreeItem(SecParam, PR_TRUE);
        SecParam = NULL;
    }

    if( EncContext != NULL ) {
        PK11_DestroyContext(EncContext, PR_TRUE);
        EncContext = NULL;
    }

    if( unwrapper != NULL ) {
        PK11_FreeSymKey( unwrapper );
        unwrapper = NULL;
    } 

    if( unwrapKeySlot != NULL) {
        PK11_FreeSlot( unwrapKeySlot);
        unwrapKeySlot = NULL;
    } 

    PR_fprintf( PR_STDOUT,
        "UnWrappedSymKey on token result: %p \n",unWrappedSymKey);

    return unWrappedSymKey;
}
//Return default keyset developer key. Either auth, mac, or kek
PK11SymKey *ReturnDeveloperSymKey(PK11SlotInfo *slot, char *keyType, char *keySet, Buffer &inputKey)
{
    const int maxKeyNameSize = 56;
    PK11SymKey *devSymKey = NULL;
    PK11SymKey *transportKey = NULL;
    char devKeyName[maxKeyNameSize];

    SECStatus rv = SECSuccess;

    BYTE sessionKey[DES3_LENGTH];

    if( slot == NULL || keyType == NULL || keySet == NULL) {
        return NULL;
    }

    snprintf(devKeyName,maxKeyNameSize,"%s-%sKey", keySet, keyType);

    devSymKey = ReturnSymKey( slot, devKeyName );
 
    // Try to create the key once and leave it there. 
    if( devSymKey == NULL ) {
        PR_fprintf(PR_STDOUT, "Can't find devSymKey, try to create it on token. \n");
        if ( inputKey.size() == DES2_LENGTH ) { //Any other size ignored
            transportKey = ReturnSymKey( slot, GetSharedSecretKeyName(NULL));

            if( transportKey == NULL) {
                PR_fprintf(PR_STDERR,"Can't get transport key in ReturnDeveloperSymKey! \n");
                goto done;
            }

            /* convert 16-byte to 24-byte triple-DES key */
            memcpy(sessionKey, inputKey, DES2_LENGTH);
            memcpy(sessionKey+ DES2_LENGTH, inputKey, EIGHT_BYTES);

            //Unwrap this thing on there as permanent, so we don't have to create it again for a given keySet.
            if( transportKey) {
                devSymKey = CreateUnWrappedSymKeyOnToken( slot, transportKey,  sessionKey, sizeof(sessionKey), PR_TRUE);
            }

            PR_fprintf(PR_STDERR,"Tried to create devSymKey %p \n",devSymKey);

            rv = SECSuccess;
            if( devSymKey ) {
                rv = PK11_SetSymKeyNickname( devSymKey,  devKeyName );

                if ( rv != SECSuccess ) {
                    PR_fprintf(PR_STDERR, "Can't set the nickname of just written devKey! \n");
                }
            }
        }
    }

done:
    if( transportKey ) {
        PK11_FreeSymKey( transportKey );
        transportKey = NULL;
    }

    // Dont' free slot , let the caller.
    return devSymKey;
}

/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    SetDefaultPrefix
 * Signature: (Ljava/lang/String;)V
 */
extern "C" JNIEXPORT void JNICALL Java_com_netscape_symkey_SessionKey_SetDefaultPrefix
(JNIEnv *, jclass, jstring);
extern "C" JNIEXPORT void
JNICALL Java_com_netscape_symkey_SessionKey_SetDefaultPrefix(JNIEnv * env, jclass this2, jstring masterPrefix)
{
    char *masterPrefixChars;

    masterPrefixChars = (char *)(env)->GetStringUTFChars(masterPrefix, NULL);

    if(masterPrefixChars)
        strcpy(masterKeyPrefix,masterPrefixChars);
    else
        masterKeyPrefix[0] = '\0';

    if(masterPrefixChars)
    {
        (env)->ReleaseStringUTFChars(masterPrefix, (const char *)masterPrefixChars);
    }

    return;
}
