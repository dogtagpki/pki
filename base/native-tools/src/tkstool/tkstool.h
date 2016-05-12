/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

/************************/
/**  #include headers  **/
/************************/

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

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

#include "secutil.h"
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


/****************/
/**  #defines  **/
/****************/

#define TKSTOOL_MAJOR_VERSION_NUMBER           1
#define TKSTOOL_MINOR_VERSION_NUMBER           0
#define TKSTOOL_VERSION_SUFFIX                 ""

#define DEFAULT_KEY_BITS                       1024
#define NUM_KEYSTROKES                         120
#define RAND_BUF_LENGTH                        60
#define DES_LENGTH                             8
#define KEYSTROKES_TO_PROCEED                  8
#define KCV_LENGTH                             4
#define CTRL_C                                 3

#define FIRST_SESSION_KEY_SHARE                "first"
#define FIRST_SESSION_KEY_SHARE_LENGTH         16
#define SECOND_SESSION_KEY_SHARE               "second"
#define SECOND_SESSION_KEY_SHARE_LENGTH        16
#define THIRD_SESSION_KEY_SHARE                "third"
#define THIRD_SESSION_KEY_SHARE_LENGTH         16
#define HEX_SESSION_KEY_BUF_LENGTH             32
#define HEX_SESSION_KEY_KCV_BUF_LENGTH         8

#define MASTER_KEY_LENGTH                      24 

#define WRAPPED_KEY_LENGTH                     16
#define HEX_WRAPPED_KEY_LENGTH                 32
#define HEX_WRAPPED_KEY_KCV_LENGTH             8

#if defined(PAD_DES2_KEY_LENGTH)
#define PADDED_FIRST_SESSION_KEY_SHARE_LENGTH  24
#define PADDED_SECOND_SESSION_KEY_SHARE_LENGTH 24
#define PADDED_THIRD_SESSION_KEY_SHARE_LENGTH  24
#endif

#define FIRST_SYMMETRIC_KEY                    "first"
#define SECOND_SYMMETRIC_KEY                   "second"
#define THIRD_SYMMETRIC_KEY                    "third"
#define MASTER_KEY                             "master"
#define RESIDENT_KEY                           "resident"
#define SESSION_KEY                            "session"
#define SYMMETRIC_KEY                          "symmetric"
#define TRANSPORT_KEY                          "transport"
#define UNWRAPPED_KEY                          "unwrapped"
#define WRAPPED_KEY                            "wrapped"

#define CONTINUATION_MESSAGE                   "Press enter to continue " \
                                               "(or ^C to break):  "

#define PROCEED_MESSAGE                        "Type the word \"proceed\" "   \
                                               "and press enter to continue " \
                                               "(or ^C to break):  "


/**************************************/
/**  external function declarations  **/
/**************************************/

#if defined(__sun) && !defined(SVR4)
extern int fclose( FILE* );
extern int fprintf( FILE *, char *, ... );
extern int isatty( int );
extern char *sys_errlist[];
#define strerror( errno ) sys_errlist[errno]
#endif


/***************************/
/**  function prototypes  **/
/***************************/

/************/
/* delete.c */
/************/

SECStatus
TKS_DeleteKeys( char *progName,
                PK11SlotInfo *slot,
                char *keyname,
                secuPWData *pwdata );


/**********/
/* file.c */
/**********/

SECStatus
TKS_ReadInputFileIntoSECItem( char    *input,
                              char    *hexInternalKeyKCV,
                              int      hexInternalKeyKCVLength,
                              char    *keyname,
                              SECItem *wrappedKey );

SECStatus
TKS_WriteSECItemIntoOutputFile( SECItem *wrappedKey,
                                char    *keyname,
                                char    *hexInternalKeyKCV,
                                int      hexInternalKeyKCVLength,
                                char    *output );


/**********/
/* find.c */
/**********/

SECStatus
TKS_FindSymKey( PK11SlotInfo *slot,
                char *keyname,
                void *pwdata );


/**********/
/* help.c */
/**********/

void
TKS_Usage( char *progName );

void
TKS_PrintHelp( char *progName );


/*********/
/* key.c */
/*********/

SECStatus
TKS_ComputeAndDisplayKCV( PRUint8    *newKey,
                          PRIntn      newKeyLen,
                          PRUint8    *KCV,
                          PRIntn      KCVLen,
                          PK11SymKey *symKey,
                          char       *keyName,
                          char       *keyType,
                          PRBool      displayKCV,
                          PRUint8    *expectedHexKCV );

SECStatus
TKS_GenerateSessionKeyShare( char    *sessionKeyShareName,
                             SECItem *sessionKeyShare );

SECStatus
TKS_InputSessionKeyShare( char    *sessionKeyShareName,
                          SECItem *sessionKeyShare );

PK11SymKey *
TKS_ImportSymmetricKey( char              *symmetricKeyName,
                        PK11SlotInfo      *slot,
                        CK_MECHANISM_TYPE  mechanism,
                        CK_ATTRIBUTE_TYPE  operation,
                        SECItem           *sessionKeyShare,
                        secuPWData        *pwdata );

PK11SymKey *
TKS_DeriveSymmetricKey( char              *symmetricKeyName,
                        PK11SymKey        *symKey,
                        CK_MECHANISM_TYPE  derive,
                        SECItem           *sessionKeyShare,
                        CK_MECHANISM_TYPE  target,
                        CK_ATTRIBUTE_TYPE  operation,
                        int                keysize );

SECStatus
TKS_StoreSymmetricKeyAndNameIt( char              *symmetricKeyName,
                                char              *keyname,
                                PK11SlotInfo      *slot,
                                CK_ATTRIBUTE_TYPE  operation,
                                CK_FLAGS           flags,
                                PK11SymKey        *symKey );


/**********/
/* list.c */
/**********/

SECStatus
TKS_ListKeys( char *progName,
              PK11SlotInfo *slot,
              char *keyname,
              int index, 
              PRBool dopriv,
              secuPWData *pwdata );


/*************/
/* modules.c */
/*************/

SECStatus
TKS_ListSecModules( void );


/************/
/* random.c */
/************/

void
TKS_FileForRNG( char *noise );

SECStatus
TKS_SeedRNG( char *noise );


/**************/
/* retrieve.c */
/**************/

PK11SymKey *
TKS_RetrieveSymKey( PK11SlotInfo *slot,
                    char *keyname,
                    void *pwdata );


/**********/
/* util.c */
/**********/

PR_IMPLEMENT( void )
TKS_ClearScreen();

PR_IMPLEMENT( void )
TKS_WaitForUser();

PR_IMPLEMENT( void )
TKS_TypeProceedToContinue();

PR_IMPLEMENT( void )
TKS_AdjustOddParity( PRUint8 *key );

PR_IMPLEMENT( void )
TKS_StringToHex( PRUint8 *key,
                 PRIntn len,
                 PRUint8 *hex_key,
                 PRIntn hex_len );

PR_IMPLEMENT( PRBool )
TKS_ConvertStringOfHexCharactersIntoBitStream( char* input,
                                               PRIntn input_bytes,
                                               PRUint8* output );


/*************/
/* version.c */
/*************/

void
TKS_Version( char *progName );

