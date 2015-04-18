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

// AC: KDF SPEC CHANGE: Include headers for NIST SP800-108 KDF functions.
#include "NistSP800_108KDF.h"

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

static int checkForDeveloperKeySet(char * keyInfo);

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
    // AC: Stop iteration if we've found the key
    while(( sk != NULL ) && (foundSymKey == NULL))
    {
        /* get the nickname of this symkey */
        name = PK11_GetSymKeyNickname( sk );

        /* if the name matches, make a 'copy' of it */
        // AC BUGFIX: Don't leak key name string memory if name isn't equal to keyname
        if ( name != NULL )
        {
            if ((foundSymKey == NULL) && (strcmp( keyname, name ) == 0))
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
PK11SymKey *ComputeCardKeyOnSoftToken(PK11SymKey *masterKey, unsigned char *data, int protocol)
{
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    PK11SymKey *key = ComputeCardKey(masterKey, data, slot,protocol);
    if( slot != NULL) {
        PK11_FreeSlot(slot);
        slot = NULL;
    }

    return key;
}

PK11SymKey *ComputeCardKey(PK11SymKey *masterKey, unsigned char *data, PK11SlotInfo *slot,int protocol)
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

    PR_fprintf(PR_STDOUT,"ComputeCardKey: protocol %d.\n",protocol);

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

PK11SymKey * ComputeCardKeyOnToken(PK11SymKey *masterKey, BYTE* data, int protocol)
{
    PK11SlotInfo *slot = PK11_GetSlotFromKey(masterKey);
    PK11SymKey *key = ComputeCardKey(masterKey, data, slot,protocol);

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
// AC: Prevent broken code from compiling.
#error "This code will not work unless DES2_WORKAROUND is defined!!!  (memcpy below writes beyond array bounds)"
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
PRStatus CreateKeySetDataWithSymKeys( Buffer &newMasterVer,const Buffer &old_kek_key2, PK11SymKey *old_kek_key2_sym, PK11SymKey *new_auth_key, PK11SymKey *new_mac_key, PK11SymKey *new_kek_key,int protocol, Buffer &output)
{
    PRStatus rv = PR_FAILURE;
    static SECItem noParams = { siBuffer, NULL, 0 };
    PK11SymKey *transportKey = NULL;
    PK11SymKey *wrappingKey = NULL;
    BYTE masterKeyData[DES3_LENGTH];
    BYTE alg = 0x81;

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

    Buffer *dumpBuffer = NULL;
    int showDerivedKeys = 0;

    PR_fprintf(PR_STDOUT,"In CreateKeySetDataWithSymKeys! Protocol: %d \n",protocol);

    if ( new_auth_key == NULL || new_mac_key == NULL || new_kek_key == NULL) {
        return rv;
    }

    slot = PK11_GetSlotFromKey(new_auth_key);

    if(protocol == 1) {
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
            PR_fprintf(PR_STDOUT,"In CreateKeySetDataWithSymKeys: SCP01 card key mode.\n");
            wrappingKey = old_kek_key2_sym;
        }

   } else if(protocol == 2) {

       PR_fprintf(PR_STDOUT,"In CreateKeySetDataWithSymKeys: Using dekKey from SCP02 for wrapping key.\n");


       // Use the unwapped SCP02 DEK sym key pointer. 
       wrappingKey = old_kek_key2_sym;

   } else {
       PR_fprintf(PR_STDERR,"Invalid protocol %d . \n",protocol);
            goto done;

   }

        //Now derive 16 byte versions of the provided symkeys
        authKey16 = PK11_Derive(new_auth_key, CKM_EXTRACT_KEY_FROM_KEY, &paramsItem, CKA_ENCRYPT,
                                                            CKA_DERIVE, 16);

        if(showDerivedKeys == 1) {
            SECItem *keyData = NULL;
            PK11_ExtractKeyValue( authKey16 ); 
            keyData = PK11_GetKeyData(authKey16);
            dumpBuffer = new Buffer(keyData->data,keyData->len  );
            PR_fprintf(PR_STDERR,"Debug authKey16 data: \n");
            dumpBuffer->dump();
            delete dumpBuffer;
            dumpBuffer = NULL;
        }

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


        if(showDerivedKeys == 1) {
            SECItem *keyData = NULL;
            PK11_ExtractKeyValue( macKey16 );
            keyData = PK11_GetKeyData(macKey16);
            dumpBuffer = new Buffer(keyData->data,keyData->len  );
            PR_fprintf(PR_STDERR,"Debug macKey16 data: \n");
            dumpBuffer->dump();
            delete dumpBuffer;
            dumpBuffer = NULL;
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

        if(showDerivedKeys == 1) {
            SECItem *keyData = NULL;
            PK11_ExtractKeyValue( kekKey16 );
            keyData = PK11_GetKeyData(kekKey16);
            dumpBuffer = new Buffer(keyData->data,keyData->len  );
            PR_fprintf(PR_STDERR,"Debug kekKey16 data: \n");
            dumpBuffer->dump();
            delete dumpBuffer;
            dumpBuffer = NULL;
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

        if(protocol == 2) {
            alg = 0x80;
        } //default at top is 0x81

        result = newMasterVer +
            Buffer(1, (BYTE)alg) +
            Buffer(1, (BYTE)0x10) +
            encrypted_auth_key +
            Buffer(1, (BYTE)0x03) +
            kc_auth_key +
            Buffer(1, (BYTE)alg) +
            Buffer(1, (BYTE)0x10) +
            encrypted_mac_key +
            Buffer(1, (BYTE)0x03) +
            kc_mac_key +
            Buffer(1, (BYTE)alg) +
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

// AC: BUGFIX for key versions higher than 09:  We need to specialDecode keyInfo parameters before sending them into symkey!
// (atoi doesn't do the same thing as specialDecode does; since we're decoding on the Java side, this function is unnecessary)
//static int getMasterKeyVersion(char *newMasterKeyNameChars)
//{
//    if( newMasterKeyNameChars == NULL ||
//        strlen( newMasterKeyNameChars) < 3) {
//        return 0;
//    }
//
//    char masterKeyVersionNumber[3];
//    masterKeyVersionNumber[0]=newMasterKeyNameChars[1];
//    masterKeyVersionNumber[1]=newMasterKeyNameChars[2];
//    masterKeyVersionNumber[2]=0;
//    int newMasterKeyVesion = atoi(masterKeyVersionNumber);
//    return newMasterKeyVesion;
//}

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
// AC: KDF SPEC CHANGE: function signature change - added jstring oldKeyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
// AC: BUGFIX for key versions higher than 09:  We need to specialDecode keyInfo parameters before sending them into symkey!  This means the parameters must be jbyteArray's
//     -- Changed parameter "jstring keyInfo" to "jbyteArray newKeyInfo"
//extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey
//(JNIEnv *, jclass, jstring, jstring, jstring, jstring, jbyteArray, jbyteArray, jbyte, jboolean, jbyteArray, jbyteArray, jbyteArray, jstring, jstring);

// AC: KDF SPEC CHANGE: function signature change - added jstring oldKeyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, and jbyteArray KDD
// AC: BUGFIX for key versions higher than 09:  We need to specialDecode keyInfo parameters before sending them into symkey!  This means the parameters must be jbyteArray's
//     -- Changed parameter "jstring keyInfo" to "jbyteArray newKeyInfo"
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey( JNIEnv * env, jclass this2, jstring tokenName,jstring newTokenName, jstring oldMasterKeyName, jstring newMasterKeyName, jbyteArray oldKeyInfo, jbyteArray newKeyInfo, jbyte nistSP800_108KdfOnKeyVersion, jboolean nistSP800_108KdfUseCuidAsKdd, jbyteArray CUIDValue, jbyteArray KDD, jbyteArray kekKeyArray, jstring useSoftToken_s, jstring keySet,jbyte protocol)
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

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF being used for old key version, we build all 3 old keys despite only using one of them (Kek) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // KDF output keys
    PK11SymKey* old_mac_sym_key = NULL;
    PK11SymKey* old_enc_sym_key = NULL;
    PK11SymKey* old_kek_sym_key = NULL;
    BYTE scp02DekKeyData[DES3_LENGTH];

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


    // AC: BUGFIX for key versions higher than 09
    // No longer need this variable (it's misspelled anyway) and it's the wrong type.
    // int newMasterKeyVesion = 1;

    // AC: BUGFIX for key versions higher than 09
    // New variables used for JNI retrieval.
    jbyte* oldKeyInfo_jbyteptr = NULL;
    jbyte* newKeyInfo_jbyteptr = NULL;
    jsize oldKeyInfo_jbyteptr_len = -1;
    jsize newKeyInfo_jbyteptr_len = -1;


    /* find slot */
    char *tokenNameChars = NULL;
    char * newMasterKeyNameChars = NULL;
    PK11SlotInfo *slot = NULL;
    PK11SlotInfo *internal = PK11_GetInternalKeySlot();

    Buffer output;
    PK11SlotInfo *newSlot =NULL;
    char * newTokenNameChars = NULL;
    //char *keyInfoChars = NULL;

    // AC: KDF SPEC CHANGE:  Need to retrieve old key info from JNI.
    //char* oldKeyInfoChars = NULL;

    // AC: KDF SPEC CHANGE:  Convert new setting value to BYTE (unsigned).
    BYTE nistSP800_108KdfOnKeyVersion_byte = static_cast<BYTE>(nistSP800_108KdfOnKeyVersion);

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    jbyte* cuidValue = NULL;
    jsize cuidValue_len = -1;
    jbyte* kddValue = NULL;
    jsize kddValue_len = -1;

    jbyte * old_kek_key = NULL;

    PK11SymKey * masterKey = NULL;
    PK11SymKey * oldMasterKey = NULL;
    PK11SymKey * transportKey = NULL;

    BYTE KDCenc[KEYLENGTH];
    BYTE KDCmac[KEYLENGTH];
    BYTE KDCkek[KEYLENGTH];

    // AC: BUGFIX for key versions higher than 09:  New code to retrieve oldKeyInfo and newKeyInfo byte arrays from JNI.
    BYTE oldKeyVersion;
    BYTE newKeyVersion;

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    bool error_computing_result = true;


    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    //                       Also added "len" variable for CUID (for sanity check).
    if ( CUIDValue != NULL ) {
        cuidValue =  (jbyte*)(env)->GetByteArrayElements( CUIDValue, NULL);
        cuidValue_len = env->GetArrayLength(CUIDValue);
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


    if( kekKeyArray != NULL) {
        old_kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);
    }

    if( old_kek_key == NULL) {
        goto done;
    }

    PR_fprintf(PR_STDOUT,"In SessionKey.DiversifyKey! Protocol: %d \n", protocol);

    // AC: KDF SPEC CHANGE:
    // Changed from "cuidValue" to "kddValue".
    //   This change is necessary due to the semantics change in the parameters passed between TPS and TKS.
    GetDiversificationData(kddValue,KDCenc,enc);
    GetDiversificationData(kddValue,KDCmac,mac);
    GetDiversificationData(kddValue,KDCkek,kek);

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

    if(masterKey == NULL) {
        goto done;
    }

    // AC: BUGFIX for key versions higher than 09:  Since "jstring keyInfo" is now passed in as "jbyteArray newKeyInfo", we no longer need this code.
    //
    ///* packing return */
    //if( keyInfo != NULL) {
    //     keyInfoChars = (char *)(env)->GetStringUTFChars(keyInfo, NULL);
    //}
    //
    //newMasterKeyVesion = getMasterKeyVersion(keyInfoChars);
    //
    //if(keyInfoChars)
    //{
    //    (env)->ReleaseStringUTFChars(keyInfo, (const char *)keyInfoChars);
    //}
    //
    ///* NEW MASTER KEY VERSION */
    //newMasterKeyBuffer = Buffer((unsigned int) 1,  (BYTE)newMasterKeyVesion);



    // AC: BUGFIX for key versions higher than 09:  New code to retrieve oldKeyInfo and newKeyInfo byte arrays from JNI.
    if (oldKeyInfo != NULL){
        oldKeyInfo_jbyteptr =  env->GetByteArrayElements(oldKeyInfo, NULL);
        oldKeyInfo_jbyteptr_len = env->GetArrayLength(oldKeyInfo);
    }
    if(oldKeyInfo_jbyteptr == NULL){
        goto done;
    }
    if (oldKeyInfo_jbyteptr_len != 2){
        goto done;
    }
    if (newKeyInfo != NULL){
        newKeyInfo_jbyteptr =  env->GetByteArrayElements(newKeyInfo, NULL);
        newKeyInfo_jbyteptr_len = env->GetArrayLength(newKeyInfo);
    }
    if(newKeyInfo_jbyteptr == NULL){
        goto done;
    }
    if (newKeyInfo_jbyteptr_len != 2){
        goto done;
    }
    // now get the key versions from the byte arrays we got from JNI
    oldKeyVersion = oldKeyInfo_jbyteptr[0];
    newKeyVersion = newKeyInfo_jbyteptr[0];
    // for compatibility with old code: wrap newKeyVersion inside Buffer object
    newMasterKeyBuffer = Buffer((unsigned int) 1,  newKeyVersion);



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

    if(protocol == 1) {
        if( checkForDeveloperKeySet(oldMasterKeyNameChars ))
        {
            old_kek_key_buff    =   Buffer((BYTE*)old_kek_key, KEYLENGTH);
        }
        else
        {
            oldMasterKey =     ReturnSymKey(slot,fullMasterKeyName);


            // AC: BUGFIX: Check for nonexistent master key instead of (potentially) crashing.
            if (oldMasterKey == NULL){
                goto done;
            }

            // ---------------------------------
            // AC KDF SPEC CHANGE: Determine which KDF to use.
            //
            // if old key version meets setting value, use NIST SP800-108 KDF for deriving old keys
            if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, oldKeyVersion) == true){

                PR_fprintf(PR_STDOUT,"DiversifyKey old key NistSP800_108KDF code: Using NIST SP800-108 KDF for old keyset.\n");

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
                    PR_fprintf(PR_STDERR, "DiversifyKey old key NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                    goto done;
                }

                // call NIST SP800-108 KDF routine
                try{
                    NistSP800_108KDF::ComputeCardKeys(oldMasterKey, context, context_len, &old_enc_sym_key, &old_mac_sym_key, &old_kek_sym_key);
                }catch(std::runtime_error& ex){
                    PR_fprintf(PR_STDERR, "DiversifyKey old key NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                    PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                    goto done;
                }catch(...){
                    PR_fprintf(PR_STDERR, "DiversifyKey old key NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                    goto done;
                }

            // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
            }else{

                PR_fprintf(PR_STDOUT,"DiversifyKey old key NistSP800_108KDF code: Using original KDF for old keyset.\n");

                // AC: Derives the kek key for the token.
                old_kek_sym_key = ComputeCardKeyOnToken(oldMasterKey,KDCkek,1);

            } // endif use original KDF
        }

    }  else if(protocol == 2) {

            Buffer dek_key_buf    =   Buffer((BYTE*)old_kek_key, 16);

            PR_fprintf(PR_STDOUT,"DiversifyKey: protocol is 2 import wrapped dek key. \n");
            dek_key_buf.dump();
            transportKey = ReturnSymKey( slot, GetSharedSecretKeyName(NULL));

            if(transportKey == NULL)
                goto done;

            /* convert 16-byte to 24-byte triple-DES key */
            memcpy(scp02DekKeyData, old_kek_key, 16);

            old_kek_sym_key = UnwrapWrappedSymKeyOnToken( slot, transportKey,DES2_LENGTH, scp02DekKeyData, PR_FALSE);
            if(old_kek_sym_key == NULL) {
                PR_fprintf(PR_STDERR,"DiversifyKey: Can't unwrap dek key for protocol 2! \n");
                goto done;
            }

        } else {
            PR_fprintf(PR_STDERR,"DiversifyKey: invalid protocol! \n");
           goto done;

        }
        // AC KDF SPEC CHANGE: Moved this code down so we don't skip it during "goto done".
        //if (oldMasterKey) {
        //    PK11_FreeSymKey( oldMasterKey );
        //    oldMasterKey = NULL;
        //}

    // AC KDF SPEC CHANGE: Moved this code down so we don't skip it during "goto done".
    //if(oldMasterKeyNameChars) {
    //    (env)->ReleaseStringUTFChars(oldMasterKeyName, (const char *)oldMasterKeyNameChars);
    //}

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

        // ---------------------------------
        // AC KDF SPEC CHANGE: Determine which KDF to use.
        //
        // if old key version meets setting value, use NIST SP800-108 KDF for deriving new keys
        if (NistSP800_108KDF::useNistSP800_108KDF(nistSP800_108KdfOnKeyVersion_byte, newKeyVersion) == true){

            PR_fprintf(PR_STDOUT,"DiversifyKey new key NistSP800_108KDF code: Using NIST SP800-108 KDF for new keyset.\n");

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
                PR_fprintf(PR_STDERR, "DiversifyKey new key NistSP800_108KDF code: Error; context_len larger than 255 bytes.\n");
                goto done;
            }

            // call NIST SP800-108 KDF routine
            try{
                NistSP800_108KDF::ComputeCardKeys(masterKey, context, context_len, &encKey, &macKey, &kekKey);
            }catch(std::runtime_error& ex){
                PR_fprintf(PR_STDERR, "DiversifyKey new key NistSP800_108KDF code: Exception invoking NistSP800_108KDF::ComputeCardKeys: ");
                PR_fprintf(PR_STDERR, "%s\n", ex.what() == NULL ? "null" : ex.what());
                goto done;
            }catch(...){
                PR_fprintf(PR_STDERR, "DiversifyKey new key NistSP800_108KDF code: Unknown exception invoking NistSP800_108KDF::ComputeCardKeys.\n");
                goto done;
            }

        // if not a key version where we use the NIST SP800-108 KDF, use the original KDF
        }else{

            PR_fprintf(PR_STDOUT,"DiversifyKey new key NistSP800_108KDF code: Using original KDF for new keyset.\n");

            // AC: Derives the kek key for the token.
            /* compute card key */
            encKey = ComputeCardKeyOnSoftToken(masterKey, KDCenc,protocol);
            macKey = ComputeCardKeyOnSoftToken(masterKey, KDCmac,protocol);
            kekKey = ComputeCardKeyOnSoftToken(masterKey, KDCkek,protocol);

        } // endif use original KDF
        // ---------------------------------

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
            protocol,
            output); }
    else {
        old_kek_sym_key =  ReturnDeveloperSymKey(slot, (char *) "kek", keySetString, old_kek_key_buff);

        CreateKeySetDataWithSymKeys(newMasterKeyBuffer, Buffer(),
            old_kek_sym_key,
            encKey,
            macKey,
            kekKey,
            protocol,
            output);
    }

done:

    // AC: BUGFIX for key versions higher than 09:  Release oldKeyInfo and newKeyInfo JNI byte arrays.
    if ( oldKeyInfo_jbyteptr != NULL){
        env->ReleaseByteArrayElements(oldKeyInfo, oldKeyInfo_jbyteptr, JNI_ABORT);
        oldKeyInfo_jbyteptr = NULL;
    }
    if ( newKeyInfo_jbyteptr != NULL){
        env->ReleaseByteArrayElements(newKeyInfo, newKeyInfo_jbyteptr, JNI_ABORT);
        newKeyInfo_jbyteptr = NULL;
    }

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

    // AC: KDF SPEC CHANGE:  For the NIST SP800-108 KDF being used for old key version, we build all 3 old keys despite only using one of them (Kek) in this function.
    //                       We do this because our NIST SP800-108 KDF outputs the data for all three keys simultaneously.
    // AC: BUGFIX: Note that there was previously no PK11_FreeSymKey(old_kek_sym_key) call.  This most likely resulted in a memory / keyhandle leak.
    if( old_mac_sym_key ) {
        PK11_FreeSymKey(old_mac_sym_key);
        old_mac_sym_key = NULL;
    }
    if ( old_enc_sym_key ) {
        PK11_FreeSymKey(old_enc_sym_key);
        old_enc_sym_key = NULL;
    }
    if ( old_kek_sym_key ) {
        PK11_FreeSymKey(old_kek_sym_key);
        old_kek_sym_key = NULL;
    }

    // AC KDF SPEC CHANGE: Moved this code down so we don't skip it during "goto done".
    if (oldMasterKey) {
        PK11_FreeSymKey( oldMasterKey );
        oldMasterKey = NULL;
    }
    if(oldMasterKeyNameChars) {
        (env)->ReleaseStringUTFChars(oldMasterKeyName, (const char *)oldMasterKeyNameChars);
        oldMasterKeyNameChars = NULL;
    }

    if( keySetStringChars ) {
        (env)->ReleaseStringUTFChars(keySet, (const char *)keySetStringChars);
        keySetStringChars = NULL;
    }

    if( specified_key_is_present )
    {
        if(output.size()>0)
            handleBA = (env)->NewByteArray( output.size());

        // AC: Bugfix: Return NULL if no output is present.
        //else
        //    handleBA = (env)->NewByteArray(1);

        // AC: Bugfix: Don't crash if we couldn't allocate array.
        if (handleBA != NULL){
            handleBytes = (env)->GetByteArrayElements(handleBA, NULL);

            // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
            if (handleBytes != NULL){
                memcpy(handleBytes, (BYTE*)output,output.size());
                error_computing_result = false;
            }
        }

        if( handleBytes != NULL) {
            (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
        }
    }

    if( cuidValue != NULL) {
        (env)->ReleaseByteArrayElements(CUIDValue, cuidValue, JNI_ABORT);
    }

    // AC: KDF SPEC CHANGE:  Need to retrieve KDD as well as CUID from JNI.
    if ( kddValue != NULL){
        env->ReleaseByteArrayElements(KDD, kddValue, JNI_ABORT);
        kddValue = NULL;
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

    // AC: BUGFIX: Don't return a java array with uninitialized or zero'd data.
    if (error_computing_result == false){
        return handleBA;
    }else{
        return NULL;
    }
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
    PK11SymKey *unwrapped24Key = NULL;

    PR_fprintf( PR_STDOUT,
        "Creating UnWrappedSymKey on  token. \n");

     if ( (slot == NULL) || (unWrappingKey == NULL) ||
           (keyToBeUnWrapped == NULL) ||
           ((sizeOfKeyToBeUnWrapped != DES3_LENGTH) && (sizeOfKeyToBeUnWrapped != DES2_LENGTH))
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

     PR_fprintf( PR_STDOUT,
        "Creating UnWrappedSymKey on  token. final len %d \n", final_len);


    if ( final_len != DES3_LENGTH && final_len != DES2_LENGTH) {
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

    if(sizeOfKeyToBeUnWrapped == DES2_LENGTH) {
       unwrapped24Key = CreateDesKey24Byte(slot, unWrappedSymKey);
       if(unwrapped24Key == NULL) {
           PR_fprintf( PR_STDERR,
        "UnwrapWrappedSymKeyOnToken . Unable to unwrap 24 byte key onto token!. \n");

       }
   }


   if(unwrapped24Key != NULL) {
       PK11_FreeSymKey( unWrappedSymKey);
       unWrappedSymKey = unwrapped24Key;
   }

 
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

    PR_fprintf(PR_STDOUT,"ReturnDeveloperSymKey! trying to find key %s. \n",devKeyName);

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
        } else {
             PR_fprintf(PR_STDOUT,"ReturnDeveloperSymKey! input key size %d. \n",inputKey.size());
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

int checkForDeveloperKeySet(char * keyInfo) 
{

    if(keyInfo == NULL)
        return 1;   

    //SCP01 or SCP02
    if(strcmp( keyInfo, "#01#01") == 0 || strcmp( keyInfo, "#FF#01") == 0)
        return 1; 
           
    //SCP02 
    if(strcmp( keyInfo, "#01#02") == 0 || strcmp( keyInfo, "#FF#02") == 0) 
        return 1; 

    return  0;
}

// Unwrap previously wrapped sym key. Assume the final output is 24 bytes DES3, this function assumes the key is wrapped already.

PK11SymKey *UnwrapWrappedSymKeyOnToken( PK11SlotInfo *slot, PK11SymKey * unWrappingKey,int sizeOfWrappedKey, unsigned char * wrappedKeyData, PRBool isPerm) {

    PK11SymKey * unWrappedSymKey = NULL;
    int final_len = DES3_LENGTH;
    SECItem unWrappedKeyItem = { siBuffer, NULL, 0};
    PK11SymKey *unwrapper = NULL;
    PK11SymKey *unwrapped24Key = NULL;


    PR_fprintf( PR_STDOUT,
        "Creating UnWrappedSymKey on  token. UnwrapWrappedSymKeyOnToken.  \n");

    if ( (slot == NULL) || (unWrappingKey == NULL) || (wrappedKeyData == NULL)) 
    {
        return NULL;
    }

    if(sizeOfWrappedKey == DES2_LENGTH) {
       PR_fprintf( PR_STDOUT,
        "UnwrapWrappedSymKeyOnToken . Given 16 byte encrypted key will have to derive a 24 byte on later. \n");
   }

   PK11SlotInfo *unwrapKeySlot = PK11_GetSlotFromKey( unWrappingKey );

   if ( unwrapKeySlot != slot ) {
       unwrapper =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, unWrappingKey);
   }

   SECItem *SecParam = PK11_ParamFromIV(CKM_DES3_ECB, NULL);
   if ( SecParam == NULL) {
       goto done;
   }

   if ( final_len != DES3_LENGTH ) {
       goto done;
   }

   unWrappedKeyItem.data = wrappedKeyData;
   unWrappedKeyItem.len  = sizeOfWrappedKey;

   /* Now try to unwrap our key into the token */
   unWrappedSymKey = PK11_UnwrapSymKeyWithFlagsPerm(unwrapper ? unwrapper : unWrappingKey,
                          CKM_DES3_ECB,SecParam, &unWrappedKeyItem,
                          CKM_DES3_ECB,
                          CKA_UNWRAP,
                          sizeOfWrappedKey, 0, isPerm );

  if(unWrappedSymKey == NULL) {
       PR_fprintf( PR_STDERR,
        "UnwrapWrappedSymKeyOnToken . Unable to unwrap key onto token!. \n");
       goto done;
   }

   if(sizeOfWrappedKey == DES2_LENGTH) {
       unwrapped24Key = CreateDesKey24Byte(slot, unWrappedSymKey);
       if(unwrapped24Key == NULL) {
           PR_fprintf( PR_STDERR,
        "UnwrapWrappedSymKeyOnToken . Unable to unwrap 24 byte key onto token!. \n");

       }
   }

done:

    if( SecParam != NULL ) {
        SECITEM_FreeItem(SecParam, PR_TRUE);
        SecParam = NULL;
    }

    if( unwrapper != NULL ) {
        PK11_FreeSymKey( unwrapper );
        unwrapper = NULL;
    }

    if( unwrapKeySlot != NULL) {
        PK11_FreeSlot( unwrapKeySlot);
        unwrapKeySlot = NULL;
    }

    if( unwrapped24Key != NULL) {
        PK11_FreeSymKey( unWrappedSymKey);
        unWrappedSymKey = unwrapped24Key;
    }

    PR_fprintf( PR_STDOUT,
        "UnwrapWrappedSymKey on token result: %p \n",unWrappedSymKey);


    return unWrappedSymKey;

}
