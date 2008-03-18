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

#include "seccomon.h"
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

    if(!strcmp( tokenNameChars, "internal" ) )
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
    PK11_FreeSlot(slot);
    return key;
}

PK11SymKey *ComputeCardKey(PK11SymKey *masterKey, unsigned char *data, PK11SlotInfo *slot)
{
    PK11SymKey *key = NULL;
    PK11Context *context = NULL;
    int keysize;
    keysize = 24;
    unsigned char *keyData = NULL;
    SECStatus s;
    int i = 0;
    int len=0;
    static SECItem noParams = { siBuffer, 0, 0 };
    unsigned char *in = data;
    PK11SymKey *tmpkey = NULL;
    unsigned char wrappedkey[24];

    keyData = (unsigned char*)malloc(keysize);

    for (i = 0;i < keysize; i++)
    {
        keyData[i] = 0x0;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT,
        masterKey,
        &noParams);

    if (context == NULL)
    {
        printf("failed to create context\n");
        goto done;
    }

    /* Part 1 */
    s = PK11_CipherOp(context, &keyData[0], &len, 8, in, 8);
    if (s != SECSuccess)
    {
        printf("failed to encryp #1\n");
        goto done;
    }
    pk11_FormatDESKey(&keyData[0], 8); /* set parity */

    /* Part 2 */
    s = PK11_CipherOp(context, &keyData[8], &len, 8, in+8, 8);
    if (s != SECSuccess)
    {
        printf("failed to encryp #2\n");
        goto done;
    }
    pk11_FormatDESKey(&keyData[8], 8);

    /* Part 3 */
    for(i = 0;i < 8;i++)
    {
        keyData[i+16] = keyData[i];
    }

#define CKF_KEY_OPERATION_FLAGS 0x000e7b00UL

    /* generate a tmp key to import the sym key */
    tmpkey = PK11_TokenKeyGenWithFlags(slot,
        CKM_DES3_KEY_GEN, 0, 0, 0,
        (CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT) & CKF_KEY_OPERATION_FLAGS,
        PR_FALSE, &pwdata);

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT,
        tmpkey,
        &noParams);

    /* encrypt the key with the master key */
    s = PK11_CipherOp(context, wrappedkey, &len, 24, keyData, 24);
    if (s != SECSuccess)
    {
        printf("failed to encryp #3\n");
        goto done;
    }

    SECItem wrappeditem;
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
    return key;
}


PK11SymKey * ComputeCardKeyOnToken(PK11SymKey *masterKey, BYTE* data)
{
    PK11SlotInfo *slot = PK11_GetSlotFromKey(masterKey);
    PK11SymKey *key = ComputeCardKey(masterKey, data, slot);
    PK11_FreeSlot(slot);
    return key;
}


PRStatus EncryptDataWithCardKey(PK11SymKey *card_key, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11Context *context = NULL;
    int i;
    SECStatus s = SECFailure;
    int len;
    static SECItem noParams = { siBuffer, 0, 0 };
    unsigned char result[8];

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, card_key,
        &noParams);
    if (context == NULL)
    {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8)
    {
        s = PK11_CipherOp(context, result, &len, 8,
            (unsigned char *)(((BYTE*)input)+i), 8);

        if (s != SECSuccess)
        {
            goto done;
        }
        output.replace(i, result, 8);
    }

    rv = PR_SUCCESS;

done:
    if (context)
    {
        PK11_DestroyContext(context, PR_TRUE);
        context = NULL;
    }
    return rv;
}


PRStatus EncryptData(Buffer &kek_key, Buffer &input, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    PK11SymKey *master = NULL;
    PK11SlotInfo *slot = NULL;
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

    /* convert 16-byte to 24-byte triple-DES key */
    memcpy(masterKeyData, (BYTE*)kek_key, 16);
#ifdef DES2_WORKAROUND
    memcpy(masterKeyData+16, (BYTE*)kek_key, 8);
#endif

    slot = PK11_GetInternalKeySlot();
    if (slot == NULL)
    {
        goto done;
    }

    master = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
        PK11_OriginGenerated, CKA_ENCRYPT, &masterKeyItem,
        CKF_ENCRYPT, PR_FALSE, 0);
    if( master == NULL)
    {
        goto done;
    }

    context = PK11_CreateContextBySymKey(CKM_DES3_ECB, CKA_ENCRYPT, master,
        &noParams);
    if (context == NULL)
    {
        goto done;
    }

    for(i = 0;i < (int)input.size();i += 8)
    {
        s = PK11_CipherOp(context, result, &len, 8,
            (unsigned char *)(((BYTE*)input)+i), 8);

        if (s != SECSuccess)
        {
            goto done;
        }
        output.replace(i, result, 8);
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
    if (master)
    {
        PK11_FreeSymKey(master);
        master = NULL;
    }

    return rv;
}


PRStatus ComputeKeyCheck(const Buffer& newKey, Buffer& output)
{
    PK11SymKey *key = NULL;
    PRStatus status = PR_FAILURE ;
    PK11SlotInfo *slot = NULL;
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
    /* convert 16-byte to 24-byte triple-DES key */
    memcpy(keyData, newKey, 16);
#ifdef DES2_WORKAROUND
    memcpy(keyData+16, newKey, 8);
#endif

    memset(value, 0, sizeof value);

    slot = PK11_GetInternalKeySlot();
    if (slot != NULL)
    {
        key = PK11_ImportSymKeyWithFlags(slot, CKM_DES3_ECB,
            PK11_OriginGenerated, CKA_ENCRYPT, &keyItem,
            CKF_ENCRYPT, PR_FALSE, 0);
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
                memset(keyData, 0, sizeof keyData);
            }
            PK11_FreeSymKey(key);
            key = NULL;

        }
        PK11_FreeSlot(slot);
    }

    return status;
}


PRStatus CreateKeySetDataWithKey( Buffer &newMasterVer, PK11SymKey *old_kek_key, Buffer &new_auth_key, Buffer &new_mac_key, Buffer &new_kek_key, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    Buffer result;
    if (old_kek_key == NULL)
    {
        result = new_auth_key + new_mac_key + new_kek_key + output ;
    }
    else
    {

        Buffer encrypted_auth_key(16);
        EncryptDataWithCardKey(old_kek_key, new_auth_key, encrypted_auth_key);
        Buffer kc_auth_key(3);
        ComputeKeyCheck(new_auth_key, kc_auth_key);

        Buffer encrypted_mac_key(16);
        EncryptDataWithCardKey(old_kek_key, new_mac_key, encrypted_mac_key);
        Buffer kc_mac_key(3);
        ComputeKeyCheck(new_mac_key, kc_mac_key);

        Buffer encrypted_kek_key(16);
        EncryptDataWithCardKey(old_kek_key, new_kek_key, encrypted_kek_key);
        Buffer kc_kek_key(3);
        ComputeKeyCheck(new_kek_key, kc_kek_key);

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
    }
    output = result;

    rv = PR_SUCCESS;
    return rv;

} /* CreateKeySetDataWithKey */


PRStatus CreateKeySetData( Buffer &newMasterVer, Buffer &old_kek_key2, Buffer &new_auth_key, Buffer &new_mac_key, Buffer &new_kek_key, Buffer &output)
{
    PRStatus rv = PR_FAILURE;

    Buffer result;
    if(old_kek_key2 ==  Buffer((BYTE*)"#00#00", 6))
    {
        result = new_auth_key + new_mac_key + new_kek_key + output ;
    } else {
        Buffer encrypted_auth_key(16);
        EncryptData(old_kek_key2, new_auth_key, encrypted_auth_key);
        Buffer kc_auth_key(3);
        ComputeKeyCheck(new_auth_key, kc_auth_key);

        Buffer encrypted_mac_key(16);
        EncryptData(old_kek_key2, new_mac_key, encrypted_mac_key);
        Buffer kc_mac_key(3);
        ComputeKeyCheck(new_mac_key, kc_mac_key);

        Buffer encrypted_kek_key(16);
        EncryptData(old_kek_key2, new_kek_key, encrypted_kek_key);
        Buffer kc_kek_key(3);
        ComputeKeyCheck(new_kek_key, kc_kek_key);

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
    }
    output = result;

    rv = PR_SUCCESS;
    return rv;
}


void GetDiversificationData(jbyte *cuidValue,BYTE *KDC,keyType keytype)
{
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

    char masterKeyVersionNumber[3];
    masterKeyVersionNumber[0]=newMasterKeyNameChars[1];
    masterKeyVersionNumber[1]=newMasterKeyNameChars[2];
    masterKeyVersionNumber[2]=0;
    int newMasterKeyVesion = atoi(masterKeyVersionNumber);
    return newMasterKeyVesion;
}


void getFullName(char * fullMasterKeyName, char * masterKeyNameChars )
{
    fullMasterKeyName[0]='\0';
    if(strlen(masterKeyPrefix)>0)
        strcpy(fullMasterKeyName,masterKeyPrefix);
    strcat(fullMasterKeyName,masterKeyNameChars);
}


/*
 * Class:     com_netscape_cms_servlet_tks_RASessionKey
 * Method:    DiversifyKey
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)[B
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey
(JNIEnv *, jclass, jstring, jstring, jstring, jstring, jstring, jbyteArray, jbyteArray, jstring);

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_netscape_symkey_SessionKey_DiversifyKey( JNIEnv * env, jclass this2, jstring tokenName,jstring newTokenName, jstring oldMasterKeyName, jstring newMasterKeyName, jstring keyInfo, jbyteArray CUIDValue, jbyteArray kekKeyArray, jstring useSoftToken_s)
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
    SECStatus s;

    jbyte * cuidValue = (jbyte*)(env)->GetByteArrayElements( CUIDValue, NULL);

    BYTE *encKeyData = NULL;
    BYTE *macKeyData = NULL;
    BYTE *kekKeyData = NULL;

    BYTE KDCenc[KEYLENGTH];
    BYTE KDCmac[KEYLENGTH];
    BYTE KDCkek[KEYLENGTH];
    jbyte * old_kek_key = (jbyte*)(env)->GetByteArrayElements(kekKeyArray, NULL);

    GetDiversificationData(cuidValue,KDCenc,enc);
    GetDiversificationData(cuidValue,KDCmac,mac);
    GetDiversificationData(cuidValue,KDCkek,kek);

    jbyteArray handleBA=NULL;
    jbyte *handleBytes=NULL;
    int newMasterKeyVesion = 1;

    /* find slot */
    char *tokenNameChars = NULL;
    PK11SlotInfo *slot = NULL;

    if(tokenName)
    {
        tokenNameChars = (char *)(env)->GetStringUTFChars(tokenName, NULL);
        slot = ReturnSlot(tokenNameChars);
        (env)->ReleaseStringUTFChars(tokenName, (const char *)tokenNameChars);
    }

    /* find masterkey */
    char * newMasterKeyNameChars = NULL;
    if(newMasterKeyName)
    {
        /* newMasterKeyNameChars  #02#01 */
        newMasterKeyNameChars=  (char *)(env)->GetStringUTFChars(newMasterKeyName, NULL);
    }

    /* fullNewMasterKeyName - no prefix #02#01 */
    getFullName(fullNewMasterKeyName,newMasterKeyNameChars);
    Buffer output;
    PK11SlotInfo *newSlot =NULL;
    char * newTokenNameChars = NULL;
    if(newTokenName)
    {
        newTokenNameChars = (char *)(env)->GetStringUTFChars(newTokenName, NULL);
        newSlot = ReturnSlot(newTokenNameChars);
        (env)->ReleaseStringUTFChars(newTokenName, (const char *)newTokenNameChars);
    }
    PK11SymKey * masterKey =    ReturnSymKey(newSlot,fullNewMasterKeyName);

    if(newMasterKeyNameChars)
    {
        (env)->ReleaseStringUTFChars(newMasterKeyName, (const char *)newMasterKeyNameChars);
    }

    /* packing return */
    char *keyInfoChars;
    keyInfoChars = (char *)(env)->GetStringUTFChars(keyInfo, NULL);
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
    }
    getFullName(fullMasterKeyName,oldMasterKeyNameChars);

    if(newSlot == NULL)
    {
        newSlot = slot;
    }
    if(strcmp( oldMasterKeyNameChars, "#01#01") == 0)
    {
        old_kek_key_buff    =   Buffer((BYTE*)old_kek_key, 16);
    }else if(strcmp( oldMasterKeyNameChars, "#00#00") == 0)
    {

        /* print Debug message - do not create real keysetdata */
        old_kek_key_buff    =       Buffer((BYTE*)"#00#00", 6);
        output              =       Buffer((BYTE*)old_kek_key, 16);
    }
    else
    {
        PK11SymKey * oldMasterKey =     ReturnSymKey(slot,fullMasterKeyName);
        old_kek_sym_key = ComputeCardKeyOnToken(oldMasterKey,KDCkek);
        if (oldMasterKey)
            PK11_FreeSymKey( oldMasterKey );
    }
    if(oldMasterKeyNameChars)
        (env)->ReleaseStringUTFChars(oldMasterKeyName, (const char *)oldMasterKeyNameChars);

    /* special case #01#01 */
    if (fullNewMasterKeyName != NULL && strcmp(fullNewMasterKeyName, "#01#01") == 0)
    {
        encKeyData = (BYTE*)old_kek_key;
        macKeyData = (BYTE*)old_kek_key;
        kekKeyData = (BYTE*)old_kek_key;
    } else {
        /* compute card key */
        encKey = ComputeCardKeyOnSoftToken(masterKey, KDCenc);
        macKey = ComputeCardKeyOnSoftToken(masterKey, KDCmac);
        kekKey = ComputeCardKeyOnSoftToken(masterKey, KDCkek);

        /* Fixes Bugscape Bug #55855: TKS crashes if specified key
         * is not present -- for each portion of the key, check if
         * the PK11SymKey is NULL before sending it to PK11_GetKeyData()!
         */
        if( encKey != NULL)
        {
            s = PK11_ExtractKeyValue(encKey);
            encKeyData = (BYTE*)(PK11_GetKeyData(encKey)->data);
        }
        else
        {
            specified_key_is_present = PR_FALSE;
            goto done;
        }
        if( macKey != NULL)
        {
            s = PK11_ExtractKeyValue(macKey);
            macKeyData = (BYTE*)(PK11_GetKeyData(macKey)->data);
        }
        else
        {
            specified_key_is_present = PR_FALSE;
            goto done;
        }
        if( kekKey != NULL)
        {
            s = PK11_ExtractKeyValue(kekKey);
            kekKeyData = (BYTE*)(PK11_GetKeyData(kekKey)->data);
        }
        else
        {
            specified_key_is_present = PR_FALSE;
            goto done;
        }

    }

    encKeyBuff      =       Buffer(encKeyData, 16);
    macKeyBuff      =       Buffer(macKeyData, 16);
    kekKeyBuff      =       Buffer(kekKeyData, 16);

    /* decide to whether to create the new key set by using a sym key or
       a buffered key */
    if (old_kek_sym_key != NULL)
    {
        CreateKeySetDataWithKey(newMasterKeyBuffer,
            old_kek_sym_key,
            encKeyBuff,
            macKeyBuff,
            kekKeyBuff,
            output);
    }
    else
    {
        CreateKeySetData(newMasterKeyBuffer,
            old_kek_key_buff,
            encKeyBuff,
            macKeyBuff,
            kekKeyBuff,
            output);
    }

done:
    if (masterKey != NULL)
        PK11_FreeSymKey( masterKey);
    if (encKey != NULL)
        PK11_FreeSymKey( encKey );
    if (macKey != NULL)
        PK11_FreeSymKey( macKey );
    if (kekKey != NULL)
        PK11_FreeSymKey( kekKey );

    if( specified_key_is_present )
    {
        if(output.size()>0)
            handleBA = (env)->NewByteArray( output.size());
        else
            handleBA = (env)->NewByteArray(1);
        handleBytes = (env)->GetByteArrayElements(handleBA, NULL);
        memcpy(handleBytes, (BYTE*)output,output.size());

        (env)->ReleaseByteArrayElements( handleBA, handleBytes, 0);
    }

    (env)->ReleaseByteArrayElements(CUIDValue, cuidValue, JNI_ABORT);

    if((newSlot != slot)&& newSlot)
        PK11_FreeSlot( newSlot );
    if( slot )
        PK11_FreeSlot( slot );

    return handleBA;

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
