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

#include "tkstool.h"

/*******************************/
/**  local private functions  **/
/*******************************/

/* returns 0 for success, -1 for failure (EOF encountered) */
static int
InputHexSessionKey( char    *sessionKeyShareName,
                    SECItem *hexSessionKeyShare )
{
    int             fd;
    int             i;
    int             count;
    int             c;
    int             rv = 0;
#ifdef XP_UNIX
    cc_t            orig_cc_min;
    cc_t            orig_cc_time;
    tcflag_t        orig_lflag;
    struct termios  tio;
#endif

    PR_fprintf( PR_STDOUT, 
                "Type in the %s session key share (or ^C to break):\n\n",
                sessionKeyShareName );
    PR_fprintf( PR_STDOUT, 
                "[    ]  [    ]  [    ]  [    ]  "
                "[    ]  [    ]  [    ]  [    ]\r" );

    /* turn off echo on stdin & return on 1 char instead of NL */
    fd = fileno( stdin );

#if defined( XP_UNIX ) && !defined( VMS )
    tcgetattr( fd, &tio );
    orig_lflag       = tio.c_lflag;
    orig_cc_min      = tio.c_cc[VMIN];
    orig_cc_time     = tio.c_cc[VTIME];
    tio.c_lflag     &= ~ECHO;
    tio.c_lflag     &= ~ICANON;
    tio.c_cc[VMIN]   = 1;
    tio.c_cc[VTIME]  = 0;
    tcsetattr( fd, TCSAFLUSH, &tio );
#endif

    /* Get user input from keyboard strokes */
    count = 0;
    while( count < HEX_SESSION_KEY_BUF_LENGTH ) {
#ifdef VMS
        c = GENERIC_GETCHAR_NOECHO();
#elif XP_UNIX
        c = getc( stdin );
#else
        c = getch();
#endif
        /* break on EOF */
        if( c == EOF ) {
            rv = -1;
            break;
        }

        /* break on ^C */
        if( c == CTRL_C ) {
            rv = -1;
            break;
        }

        /* save acceptable hex characters; silently throw anything else away */
        switch( c ) {
            case '\010':  /* backspace */
                /* acceptable character; save it as a NULL value */
                hexSessionKeyShare->data[count] = '\0';
                break;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                /* acceptable character; save it as typed */
                hexSessionKeyShare->data[count] = c;
                break;
            case 'A':
            case 'a':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'A';
                break;
            case 'B':
            case 'b':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'B';
                break;
            case 'C':
            case 'c':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'C';
                break;
            case 'D':
            case 'd':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'D';
                break;
            case 'E':
            case 'e':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'E';
                break;
            case 'F':
            case 'f':
                /* acceptable character; save uppercase version */
                hexSessionKeyShare->data[count] = 'F';
                break;
            default:
                /* unacceptable character; don't save it */
                continue;
        }

        /* adjust the character count appropriately */
        if( c != '\010' ) {
            /* only increment the character count if everything is OK */
            count++;
        } else {
            /* only decrement the character count if a backspace was entered */
            if( count > 0 ) {
                count--;
            }
        }

        /* redisplay the left bracket */
        PR_fprintf( PR_STDOUT,
                    "\r[" );

        /* display the characters input so far */
        for( i = 0 ; i < count ; i++ ) {
            PR_fprintf( PR_STDOUT,
                        "%c",
                        hexSessionKeyShare->data[i] );
            if( ( i > 0 ) &&
                ( ( ( i + 1 ) % 4 ) == 0 ) ) {
                PR_fprintf( PR_STDOUT, "]  [" );
            }
        }

        /* display a "cursor" pointing to the next character */
        PR_fprintf( PR_STDOUT,
                    "/" );

        /* display spaces to pad the remainder */
        for( i = ( count + 1 );
             i < HEX_SESSION_KEY_BUF_LENGTH;
             i++ ) {
                if( ( i % 4 ) != 0 ) {
                    PR_fprintf( PR_STDOUT, " " );
                } else {
                    if( ( i > 0 ) &&
                        ( ( i + 1 ) < HEX_SESSION_KEY_BUF_LENGTH ) ) {
                            PR_fprintf( PR_STDOUT, "]  [" );
                            PR_fprintf( PR_STDOUT, " " );
                    }
                }
        }

        /* redisplay the right bracket */
        PR_fprintf( PR_STDOUT,
                    "]" );
    }

    /* Null terminate the entered character sequence */
    hexSessionKeyShare->data[count] = '\0';


    /**************************************/
    /* Print the final character sequence */
    /**************************************/

    /* Clear input line by outputting 78 blank */
    /* spaces from the beginning of this line  */
    PR_fprintf( PR_STDOUT,
                "\r"
                "                                       "
                "                                       " );

    /* Print appropriate key share name */
    PR_fprintf( PR_STDOUT,
                "\r    %s session key share:      ",
                sessionKeyShareName );

    /* Print first DES_LENGTH bytes */
    count = ( ( hexSessionKeyShare->len - 1 ) / 2 );
    for( i = 0; i < count; i += 4 ) {
        PR_fprintf( PR_STDOUT,
                    "%c%c%c%c ",
                    hexSessionKeyShare->data[i],
                    hexSessionKeyShare->data[i + 1],
                    hexSessionKeyShare->data[i + 2],
                    hexSessionKeyShare->data[i + 3] );
    }

    /* Print appropriate key share padding length */
    PR_fprintf( PR_STDOUT, "\n                             " );
    for( i = 0; i < PL_strlen( sessionKeyShareName ); i++ ) {
        PR_fprintf( PR_STDOUT, " " );
    }

    /* Print second DES_LENGTH bytes */
    for( i = count; i < hexSessionKeyShare->len; i += 4 ) {
        PR_fprintf( PR_STDOUT,
                    "%c%c%c%c ",
                    hexSessionKeyShare->data[i],
                    hexSessionKeyShare->data[i + 1],
                    hexSessionKeyShare->data[i + 2],
                    hexSessionKeyShare->data[i + 3] );
    }

    /* Print appropriate vertical spacing */
    PR_fprintf( PR_STDOUT, "\n\n\n" );

#if defined( XP_UNIX ) && !defined( VMS )
    /* set back termio the way it was */
    tio.c_lflag     = orig_lflag;
    tio.c_cc[VMIN]  = orig_cc_min;
    tio.c_cc[VTIME] = orig_cc_time;
    tcsetattr( fd, TCSAFLUSH, &tio );
#endif

    return rv;
}


/* returns 0 for success, -1 for failure (EOF encountered) */
static int
InputHexKCV( char    *sessionKeyShareName,
             PRUint8 *hexKCV )
{
    int             fd;
    int             i;
    int             count;
    int             c;
    int             rv = 0;
#ifdef XP_UNIX
    cc_t            orig_cc_min;
    cc_t            orig_cc_time;
    tcflag_t        orig_lflag;
    struct termios  tio;
#endif

    PR_fprintf( PR_STDOUT, 
                "Type in the corresponding KCV for the "
                "%s session key share (or ^C to break):\n\n",
                sessionKeyShareName );
    PR_fprintf( PR_STDOUT, 
                "[    ]  [    ]\r" );

    /* turn off echo on stdin & return on 1 char instead of NL */
    fd = fileno( stdin );

#if defined( XP_UNIX ) && !defined( VMS )
    tcgetattr( fd, &tio );
    orig_lflag       = tio.c_lflag;
    orig_cc_min      = tio.c_cc[VMIN];
    orig_cc_time     = tio.c_cc[VTIME];
    tio.c_lflag     &= ~ECHO;
    tio.c_lflag     &= ~ICANON;
    tio.c_cc[VMIN]   = 1;
    tio.c_cc[VTIME]  = 0;
    tcsetattr( fd, TCSAFLUSH, &tio );
#endif

    /* Get user input from keyboard strokes */
    count = 0;
    while( count < HEX_SESSION_KEY_KCV_BUF_LENGTH ) {
#ifdef VMS
        c = GENERIC_GETCHAR_NOECHO();
#elif XP_UNIX
        c = getc( stdin );
#else
        c = getch();
#endif
        /* break on EOF */
        if( c == EOF ) {
            rv = -1;
            break;
        }

        /* break on ^C */
        if( c == CTRL_C ) {
            rv = -1;
            break;
        }

        /* save acceptable hex characters; silently throw anything else away */
        switch( c ) {
            case '\010':  /* backspace */
                /* acceptable character; save it as a NULL value */
                hexKCV[count] = '\0';
                break;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                /* acceptable character; save it as typed */
                hexKCV[count] = c;
                break;
            case 'A':
            case 'a':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'A';
                break;
            case 'B':
            case 'b':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'B';
                break;
            case 'C':
            case 'c':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'C';
                break;
            case 'D':
            case 'd':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'D';
                break;
            case 'E':
            case 'e':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'E';
                break;
            case 'F':
            case 'f':
                /* acceptable character; save uppercase version */
                hexKCV[count] = 'F';
                break;
            default:
                /* unacceptable character; don't save it */
                continue;
        }

        /* adjust the character count appropriately */
        if( c != '\010' ) {
            /* only increment the character count if everything is OK */
            count++;
        } else {
            /* only decrement the character count if a backspace was entered */
            if( count > 0 ) {
                count--;
            }
        }

        /* redisplay the left bracket */
        PR_fprintf( PR_STDOUT,
                    "\r[" );

        /* display the characters input so far */
        for( i = 0 ; i < count ; i++ ) {
            PR_fprintf( PR_STDOUT,
                        "%c",
                        hexKCV[i] );
            if( ( i > 0 ) &&
                ( ( ( i + 1 ) % 4 ) == 0 ) ) {
                PR_fprintf( PR_STDOUT, "]  [" );
            }
        }

        /* display a "cursor" pointing to the next character */
        PR_fprintf( PR_STDOUT,
                    "/" );

        /* display spaces to pad the remainder */
        for( i = ( count + 1 );
             i < HEX_SESSION_KEY_KCV_BUF_LENGTH;
             i++ ) {
                if( ( i % 4 ) != 0 ) {
                    PR_fprintf( PR_STDOUT, " " );
                } else {
                    if( ( i > 0 ) &&
                        ( ( i + 1 ) < HEX_SESSION_KEY_KCV_BUF_LENGTH ) ) {
                            PR_fprintf( PR_STDOUT, "]  [" );
                            PR_fprintf( PR_STDOUT, " " );
                    }
                }
        }

        /* redisplay the right bracket */
        PR_fprintf( PR_STDOUT,
                    "]" );
    }

    /* Null terminate the entered character sequence */
    hexKCV[count] = '\0';


    /**************************************/
    /* Print the final character sequence */
    /**************************************/

    /* Clear input line by outputting 78 blank */
    /* spaces from the beginning of this line  */
    PR_fprintf( PR_STDOUT,
                "\r"
                "                                       "
                "                                       " );

    /* display this session key share's entered KCV value (in hex) */
    PR_fprintf( PR_STDOUT,
                "\r    %s session key share KCV:  "
                "%c%c%c%c %c%c%c%c\n\n\n",
                sessionKeyShareName,
                hexKCV[0],
                hexKCV[1],
                hexKCV[2],
                hexKCV[3],
                hexKCV[4],
                hexKCV[5],
                hexKCV[6],
                hexKCV[7] );

#if defined( XP_UNIX ) && !defined( VMS )
    /* set back termio the way it was */
    tio.c_lflag     = orig_lflag;
    tio.c_cc[VMIN]  = orig_cc_min;
    tio.c_cc[VTIME] = orig_cc_time;
    tcsetattr( fd, TCSAFLUSH, &tio );
#endif

    return rv;
}


/************************************/
/**  public session key functions  **/
/************************************/

SECStatus
TKS_ComputeAndDisplayKCV( PRUint8    *newKey,
                          PRIntn      newKeyLen,
                          PRUint8    *KCV,
                          PRIntn      KCVLen,
                          PK11SymKey *symKey,
                          char       *keyName,
                          char       *keyType,
                          PRBool      displayKCV,
                          PRUint8    *expectedHexKCV )
{
    int           len;
    unsigned char value[8];
    PK11SymKey   *key       = NULL;
    PK11SlotInfo *slot      = NULL;
    PK11Context  *context   = NULL;
    PRIntn        hexKCVLen = ( 2 * KCVLen ) + 1;
    PRUint8      *hexKCV    = NULL;
    PRUint8      *keyData   = NULL;
    SECItem       keyItem   = { siBuffer,
                                NULL,
                                0 };
    SECItem       noParams  = { siBuffer,
                                NULL,
                                0 };
    SECStatus     s         = SECFailure;
    SECStatus     status    = SECFailure;

    /* for all keys except keys that are resident/wrapped/unwrapped . . . */
    if( ( PL_strcmp( keyType, RESIDENT_KEY ) != 0 )   &&
        ( PL_strcmp( keyType, UNWRAPPED_KEY ) != 0 ) &&
        ( PL_strcmp( keyType, WRAPPED_KEY ) != 0 ) ) {
        slot = PK11_GetInternalKeySlot();

        if( newKeyLen == ( 2 * DES_LENGTH ) ) {
#if defined(PAD_DES2_KEY_LENGTH)
            /* double-DES key */
            keyData = ( PRUint8 * ) PORT_ZAlloc( newKeyLen + DES_LENGTH );

            keyItem.type = ( SECItemType ) siBuffer;
            keyItem.data = ( unsigned char * ) keyData;
            keyItem.len  = ( unsigned int ) ( newKeyLen + DES_LENGTH );

            /* convert 16-byte double-DES key to 24-byte triple-DES key */
            PORT_Memcpy( keyData, newKey, newKeyLen );
            PORT_Memcpy( ( keyData + ( 2 * DES_LENGTH ) ),
                         newKey, DES_LENGTH );
#else
            /* double-DES key */
            keyData = ( PRUint8 * ) PORT_ZAlloc( newKeyLen  );

            keyItem.type = ( SECItemType ) siBuffer;
            keyItem.data = ( unsigned char * ) keyData;
            keyItem.len  = ( unsigned int ) newKeyLen;

            PORT_Memcpy( keyData, newKey, newKeyLen );
#endif
        } else if( newKeyLen == ( 3 * DES_LENGTH ) ) {
            /* triple-DES key */
            keyData = ( PRUint8 * ) PORT_ZAlloc( newKeyLen  );

            keyItem.type = ( SECItemType ) siBuffer;
            keyItem.data = ( unsigned char * ) keyData;
            keyItem.len  = ( unsigned int ) newKeyLen;

            PORT_Memcpy( keyData, newKey, newKeyLen );
        } else {
            /* invalid key size */
            PR_fprintf( PR_STDOUT,
                        "Attempting to perform KCV on invalid key length!\n\n\n" );
            status = SECFailure;
            goto done;
        }

        key = PK11_ImportSymKeyWithFlags(
              /* slot           */        slot,
              /* mechanism type */        CKM_DES3_ECB,
              /* origin         */        PK11_OriginGenerated,
              /* operation      */        CKA_ENCRYPT,
              /* key            */        &keyItem,
              /* flags          */        CKF_ENCRYPT,
              /* isPerm         */        PR_FALSE,
              /* wincx          */        0 );

        if( ! key ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to import %s key!\n\n\n",
                        keyType );
            status = SECFailure;
            goto done;
        }
    } else {
        /* since resident/wrapped/unwrapped keys are already present . . . */
        key = symKey;
    }

    PORT_Memset( value, 0, sizeof( value ) );

    context = PK11_CreateContextBySymKey(
              /* mechanism type */        CKM_DES3_ECB,
              /* operation      */        CKA_ENCRYPT,
              /* symmetric key  */        key,
              /* param          */        &noParams );

    if( ! context ) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  Failed to create crypto context!\n\n\n" );
        status = SECFailure;
        goto done;
    }

    s = PK11_CipherOp(
        /* context               */  context,
        /* output                */  &value[0],
        /* output length         */  &len,
        /* maximum output length */  DES_LENGTH,
        /* input                 */  &value[0],
        /* input length          */  DES_LENGTH );
    if( s != SECSuccess) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  CipherOp Failed!\n\n\n" );
        status = SECFailure;
        goto done;
    }

    KCV = ( PRUint8 * ) PORT_ZAlloc( KCVLen );

    PORT_Memcpy( KCV, value, KCVLen );

    /* Create a clean new display buffer for this */
    /* symmetric key/session key share KCV        */
    hexKCV = ( PRUint8 * ) PORT_ZAlloc( hexKCVLen );
    if( hexKCV == NULL ) {
        status = SECFailure;
        goto done;
    }

    /* Display the symmetric key/session key share KCV (in hex digits) */
    TKS_StringToHex( ( PRUint8 * ) KCV,
                     ( PRIntn )    KCVLen,
                     ( PRUint8 * ) hexKCV,
                     ( PRIntn )    hexKCVLen );

    if( displayKCV != PR_FALSE ) {
        /********************************************/
        /* The following code is ONLY relevant to:  */
        /*                                          */
        /*     (1) resident,                        */
        /*     (2) session,                         */
        /*     (3) symmetric, and                   */
        /*     (4) transport keys.                  */
        /*                                          */
        /********************************************/

        if( PL_strcmp( keyType, RESIDENT_KEY ) == 0 ) {
            /* display this resident key's computed KCV value (in hex) */
            PR_fprintf( PR_STDOUT,
                        "    %s key KCV:  "
                        "%c%c%c%c %c%c%c%c\n\n\n",
                        keyName,
                        hexKCV[0],
                        hexKCV[1],
                        hexKCV[2],
                        hexKCV[3],
                        hexKCV[4],
                        hexKCV[5],
                        hexKCV[6],
                        hexKCV[7] );
        } else if( PL_strcmp( keyType, SESSION_KEY ) == 0 ) {
            /* display this session key share's computed KCV value (in hex) */
            PR_fprintf( PR_STDOUT,
                        "    %s session key share KCV:  "
                        "%c%c%c%c %c%c%c%c\n\n\n",
                        keyName,
                        hexKCV[0],
                        hexKCV[1],
                        hexKCV[2],
                        hexKCV[3],
                        hexKCV[4],
                        hexKCV[5],
                        hexKCV[6],
                        hexKCV[7] );
        } else if( PL_strcmp( keyType, SYMMETRIC_KEY ) == 0 ) {
            /* display this symmetric key's computed KCV value (in hex) */
            PR_fprintf( PR_STDOUT,
                        "    %s key KCV:  "
                        "%c%c%c%c %c%c%c%c\n\n\n",
                        keyName,
                        hexKCV[0],
                        hexKCV[1],
                        hexKCV[2],
                        hexKCV[3],
                        hexKCV[4],
                        hexKCV[5],
                        hexKCV[6],
                        hexKCV[7] );
        } else if( PL_strcmp( keyType, TRANSPORT_KEY ) == 0 ) {
            /* display this transport key's computed KCV value (in hex) */
            PR_fprintf( PR_STDOUT,
                        "    %s key KCV:  "
                        "%c%c%c%c %c%c%c%c\n\n\n",
                        keyName,
                        hexKCV[0],
                        hexKCV[1],
                        hexKCV[2],
                        hexKCV[3],
                        hexKCV[4],
                        hexKCV[5],
                        hexKCV[6],
                        hexKCV[7] );
        }
    } else {
        /**********************************************/
        /* The following code is ONLY relevant to:    */
        /*                                            */
        /*     (1) session keys,                      */
        /*     (2) keys that have been unwrapped, and */
        /*     (3) keys that will be wrapped.         */
        /*                                            */
        /**********************************************/

        if( PL_strcmp( keyType, SESSION_KEY ) == 0 ) {
            /* compare this session key share's computed KCV value (in hex) */
            /* with the expected KCV value (in hex)                         */
            if( PL_strcmp( ( const char * ) hexKCV,
                           ( const char * ) expectedHexKCV ) == 0 ) {
                PR_fprintf( PR_STDOUT,
                            "Congratulations, the %s session key share KCV "
                            "value entered CORRESPONDS\nto the %s session key "
                            "share value entered!\n",
                            keyName,
                            keyName );

                /* Wait for the user to type "proceed" to continue */
                TKS_TypeProceedToContinue();
            } else {
                PR_fprintf( PR_STDOUT,
                            "Unfortunately, a MISMATCH exists between the %s "
                            "session key share entered\nand the %s session key "
                            "share KCV entered.  Please try again . . .\n",
                            keyName,
                            keyName );

                /* Wait for the user to type "proceed" to continue */
                TKS_TypeProceedToContinue();

                status = SECFailure;
                goto done;
            }
        } else if( PL_strcmp( keyType, UNWRAPPED_KEY ) == 0 ) {
            PR_fprintf( PR_STDOUT,
                        "    master key KCV:  "
                        "%c%c%c%c %c%c%c%c\n    (computed KCV of the "
                        "master key residing inside the wrapped data)\n\n\n",
                        hexKCV[0],
                        hexKCV[1],
                        hexKCV[2],
                        hexKCV[3],
                        hexKCV[4],
                        hexKCV[5],
                        hexKCV[6],
                        hexKCV[7] );

            PR_fprintf( PR_STDOUT,
                        "    master key KCV:  "
                        "%c%c%c%c %c%c%c%c\n    (pre-computed KCV of the "
                        "master key residing inside the wrapped data)\n\n\n",
                        expectedHexKCV[0],
                        expectedHexKCV[1],
                        expectedHexKCV[2],
                        expectedHexKCV[3],
                        expectedHexKCV[4],
                        expectedHexKCV[5],
                        expectedHexKCV[6],
                        expectedHexKCV[7] );

            /* compare this wrapped key's computed KCV value (in hex) */
            /* with the expected KCV value (in hex) -- silently       */
            if( PL_strcmp( ( const char * ) hexKCV,
                           ( const char * ) expectedHexKCV ) != 0 ) {
                PR_fprintf( PR_STDOUT,
                            "Unfortunately, a MISMATCH exists between the "
                            "wrapped data read in\nfrom the input file "
                            "and the master key KCV that was recomputed.\n\n",
                            keyName,
                            keyName );
                status = SECFailure;
                goto done;
            }
        } else if( PL_strcmp( keyType, WRAPPED_KEY ) == 0 ) {
            /* store this master key's computed KCV value (in hex) */
            expectedHexKCV[0] = hexKCV[0];
            expectedHexKCV[1] = hexKCV[1];
            expectedHexKCV[2] = hexKCV[2];
            expectedHexKCV[3] = hexKCV[3];
            expectedHexKCV[4] = hexKCV[4];
            expectedHexKCV[5] = hexKCV[5];
            expectedHexKCV[6] = hexKCV[6];
            expectedHexKCV[7] = hexKCV[7];
        }
    }

    status = SECSuccess;

done:
    if( keyItem.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    keyItem.data,
                    keyItem.len );
        keyItem.data = NULL;
        keyItem.len  = 0;
    }

    if( hexKCV != NULL ) {
        PORT_ZFree( ( PRUint8 * )
                    hexKCV,
                    hexKCVLen );
    }

    if( context ) {
        PK11_DestroyContext( 
        /* context */        context,
        /* free it */        PR_TRUE );
    }

    if( slot ) {
        PK11_FreeSlot( /* slot */  slot );
    }

    /* for all keys except keys that are resident/wrapped/unwrapped . . . */
    if( ( PL_strcmp( keyType, RESIDENT_KEY ) != 0 ) &&
        ( PL_strcmp( keyType, UNWRAPPED_KEY ) != 0 ) &&
        ( PL_strcmp( keyType, WRAPPED_KEY ) != 0 ) ) {
        if( key ) {
            PK11_FreeSymKey( /* symmetric key */  key );
        }
    }

    return status;
}


SECStatus
TKS_GenerateSessionKeyShare( char    *sessionKeyShareName,
                             SECItem *sessionKeyShare )
{
    PRIntn       count                 = 0;
    PRIntn       i                     = 0;
    PRIntn       KCVLen                = KCV_LENGTH;
    PRUint8     *KCV                   = NULL;
    SECItem      hexSessionKeyShare    = { siBuffer,
                                           NULL,
                                           0 };
    SECStatus    rvKCV                 = SECFailure;
    SECStatus    sessionKeyShareStatus = SECFailure;
    SECStatus    status                = SECFailure;

    /* Clear the screen */
    TKS_ClearScreen();

    /* Generate a new session key share */
    PR_fprintf( PR_STDOUT,
                "\nGenerating the %s session key share . . .\n\n\n",
                sessionKeyShareName );

    sessionKeyShareStatus = PK11_GenerateRandom( ( unsigned char * )
                            /* data   */         sessionKeyShare->data,
                            /* length */         sessionKeyShare->len );
    if( sessionKeyShareStatus != SECSuccess ) {
        goto destroyHexSessionKeyShare;
    }

    /* Create a clean new display buffer for this session key share */
    hexSessionKeyShare.type = ( SECItemType ) siBuffer;
    hexSessionKeyShare.len  = ( ( sessionKeyShare->len * 2 ) + 1 );
    hexSessionKeyShare.data = ( unsigned char * )
                              PORT_ZAlloc( hexSessionKeyShare.len );
    if( hexSessionKeyShare.data == NULL ) {
        goto destroyHexSessionKeyShare;
    }

    /* Convert this session key share into hex digits */
    TKS_StringToHex( ( PRUint8 * ) sessionKeyShare->data,
                     ( PRIntn )    sessionKeyShare->len,
                     ( PRUint8 * ) hexSessionKeyShare.data,
                     ( PRIntn )    hexSessionKeyShare.len );

    /* Adjust the first DES-sized (8-byte) chunk */
    TKS_AdjustOddParity( ( PRUint8 * ) sessionKeyShare->data );

    /* Adjust the second DES-sized (8-byte) chunk */
    TKS_AdjustOddParity( ( PRUint8 * ) ( sessionKeyShare->data + DES_LENGTH ) );
  
    /* Finally, display this session key share */
    /* (adjusted for odd parity in hex digits) */
    TKS_StringToHex( ( PRUint8 * ) sessionKeyShare->data,
                     ( PRIntn )    sessionKeyShare->len,
                     ( PRUint8 * ) hexSessionKeyShare.data,
                     ( PRIntn )    hexSessionKeyShare.len );

    if( ( ( hexSessionKeyShare.len - 1 ) % 4 ) != 0 ) {
        /* invalid key length */
        PR_fprintf( PR_STDERR,
                    "ERROR:  Invalid session key share length "
                    "of %d bytes!\n\n\n",
                    hexSessionKeyShare.len );
        goto destroyHexSessionKeyShare;
    } else {
        /* Print appropriate key share name */
        PR_fprintf( PR_STDOUT,
                    "    %s session key share:      ",
                    sessionKeyShareName );

        /* Print first DES_LENGTH bytes */
        count = ( ( hexSessionKeyShare.len - 1 ) / 2 );
        for( i = 0; i < count; i += 4 ) {
            PR_fprintf( PR_STDOUT,
                        "%c%c%c%c ",
                        hexSessionKeyShare.data[i],
                        hexSessionKeyShare.data[i + 1],
                        hexSessionKeyShare.data[i + 2],
                        hexSessionKeyShare.data[i + 3] );
        }

        /* Print appropriate key share padding length */
        PR_fprintf( PR_STDOUT, "\n                             " );
        for( i = 0; i < PL_strlen( sessionKeyShareName ); i++ ) {
            PR_fprintf( PR_STDOUT, " " );
        }

        /* Print second DES_LENGTH bytes */
        for( i = count; i < hexSessionKeyShare.len; i += 4 ) {
            PR_fprintf( PR_STDOUT,
                        "%c%c%c%c ",
                        hexSessionKeyShare.data[i],
                        hexSessionKeyShare.data[i + 1],
                        hexSessionKeyShare.data[i + 2],
                        hexSessionKeyShare.data[i + 3] );
        }

        /* Print appropriate vertical spacing */
        PR_fprintf( PR_STDOUT, "\n\n\n" );
    }
  
    rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) sessionKeyShare->data,
                                      ( PRIntn )    sessionKeyShare->len,
                                      ( PRUint8 * ) KCV,
                                      ( PRIntn )    KCVLen,
                                                    NULL,
                                                    sessionKeyShareName,
                                                    SESSION_KEY,
                                                    PR_TRUE,
                                                    NULL );
    if( rvKCV != SECSuccess ) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  Failed to compute KCV of "
                    "this %s session key share!\n\n",
                    sessionKeyShareName );
        goto destroyHexSessionKeyShare;
    }

    PR_fprintf( PR_STDOUT,
                "(1) Write down and save the value "
                "for this %s session key share.\n\n",
                sessionKeyShareName );

    PR_fprintf( PR_STDOUT,
                "(2) Write down and save the KCV value "
                "for this %s session key share.\n",
                sessionKeyShareName );

    /* Wait for the user to type "proceed" to continue */
    TKS_TypeProceedToContinue();

    /* Clear the screen */
    TKS_ClearScreen();

    /* Report success */
    status = SECSuccess;

destroyHexSessionKeyShare:
    /* Destroy the hex session key share */
    if( hexSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexSessionKeyShare.data,
                    hexSessionKeyShare.len );
        hexSessionKeyShare.data = NULL;
        hexSessionKeyShare.len  = 0;
    }

    return status;
}

SECStatus
TKS_InputSessionKeyShare( char    *sessionKeyShareName,
                          SECItem *sessionKeyShare )
{
    int          rv                    = 0;
    PRIntn       KCVLen                = KCV_LENGTH;
    PRUint8     *KCV                   = NULL;
    SECItem      hexSessionKeyShare;
    PRIntn       hexKCVLen             = ( 2 * KCVLen ) + 1;
    PRUint8     *hexKCV                = NULL;
    SECStatus    rvKCV                 = SECFailure;
    SECStatus    status                = SECFailure;

    /* Clear the screen */
    TKS_ClearScreen();

    /* Enter a new session key share */
    PR_fprintf( PR_STDOUT,
                "\nEnter the %s session key share . . .\n\n\n",
                sessionKeyShareName );

    /* Create a clean new display buffer for this session key share */
    hexSessionKeyShare.type = ( SECItemType ) siBuffer;
    hexSessionKeyShare.len  = ( ( sessionKeyShare->len * 2 ) + 1 );
    hexSessionKeyShare.data = ( unsigned char * )
                              PORT_ZAlloc( hexSessionKeyShare.len );
    if( hexSessionKeyShare.data == NULL ) {
        goto destroyHexSessionKeyShare;
    }

    rv = InputHexSessionKey( sessionKeyShareName,
                             &hexSessionKeyShare );
    if( rv ) {
        PORT_SetError( PR_END_OF_FILE_ERROR );
        return SECFailure;
    }

    /* Convert these hex digits into a session key share */
    TKS_ConvertStringOfHexCharactersIntoBitStream( ( char * ) hexSessionKeyShare.data,
                                                   ( hexSessionKeyShare.len - 1 ),
                                                   sessionKeyShare->data );

    /* Create a clean new display buffer for this session key share KCV */
    hexKCV = ( PRUint8 * ) PORT_ZAlloc( hexKCVLen );
    if( hexKCV == NULL ) {
        goto destroyHexSessionKeyShare;
    }

    rv = InputHexKCV( sessionKeyShareName,
                      hexKCV );
    if( rv ) {
        PORT_SetError( PR_END_OF_FILE_ERROR );
        return SECFailure;
    }

    /* Enter the corresponding KCV */
    PR_fprintf( PR_STDOUT,
                "Verifying that this session key share and KCV "
                "correspond to each other . . .\n\n\n" );

    rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) sessionKeyShare->data,
                                      ( PRIntn )    sessionKeyShare->len,
                                      ( PRUint8 * ) KCV,
                                      ( PRIntn )    KCVLen,
                                                    NULL,
                                                    sessionKeyShareName,
                                                    SESSION_KEY,
                                                    PR_FALSE,
                                                    hexKCV );
    if( rvKCV != SECSuccess ) {
        goto destroyHexSessionKeyShare;
    }

    /* Clear the screen */
    TKS_ClearScreen();

    /* Report success */
    status = SECSuccess;

destroyHexSessionKeyShare:
    /* Destroy the hex session key share */
    if( hexSessionKeyShare.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexSessionKeyShare.data,
                    hexSessionKeyShare.len );
        hexSessionKeyShare.data = NULL;
        hexSessionKeyShare.len  = 0;
    }

    if( hexKCV != NULL ) {
        PORT_ZFree( ( PRUint8 * )
                    hexKCV,
                    hexKCVLen );
    }

    return status;
}


/**************************************/
/**  public symmetric key functions  **/
/**************************************/

PK11SymKey *
TKS_ImportSymmetricKey( char              *symmetricKeyName,
                        PK11SlotInfo      *slot,
                        CK_MECHANISM_TYPE  mechanism,
                        CK_ATTRIBUTE_TYPE  operation,
                        SECItem           *sessionKeyShare,
                        secuPWData        *pwdata )
{
    PK11Origin  origin = PK11_OriginGenerated;
    PK11SymKey *symKey = NULL;

    if( slot == NULL ) {
        return NULL;
    }

    PR_fprintf( PR_STDOUT,
                "\n" );
    PR_fprintf( PR_STDOUT,
                "Generating %s symmetric key . . .\n\n",
                symmetricKeyName );

    symKey = PK11_ImportSymKeyWithFlags( 
             /* slot           */        slot,
             /* mechanism type */        mechanism,
             /* origin         */        origin,
             /* operation      */        operation,
             /* key            */        sessionKeyShare,
             /* flags          */        0,
             /* isPerm         */        PR_FALSE,
             /* wincx          */        pwdata );
    return symKey;
}


PK11SymKey *
TKS_DeriveSymmetricKey( char              *symmetricKeyName,
                        PK11SymKey        *symKey,
                        CK_MECHANISM_TYPE  derive,
                        SECItem           *sessionKeyShare,
                        CK_MECHANISM_TYPE  target,
                        CK_ATTRIBUTE_TYPE  operation,
                        int                keysize )
{
    PK11SymKey *newSymKey = NULL;

    if( symKey == NULL ) {
        return NULL;
    }

    if( keysize <= 0 ) {
        return NULL;
    }

    PR_fprintf( PR_STDOUT,
                "Generating %s symmetric key . . .\n\n",
                symmetricKeyName );

    newSymKey = PK11_Derive(
    /* base symmetric key    */  symKey,
    /* mechanism derive type */  derive,
    /* param                 */  sessionKeyShare,
    /* target                */  target,
    /* operation             */  operation,
    /* key size              */  keysize );
    return newSymKey;
}


SECStatus
TKS_StoreSymmetricKeyAndNameIt( char              *symmetricKeyName,
                                char              *keyname,
                                PK11SlotInfo      *slot,
                                CK_ATTRIBUTE_TYPE  operation,
                                CK_FLAGS           flags,
                                PK11SymKey        *symKey )
{
    PK11SymKey *newSymKey             = NULL;
    PRIntn      KCVLen                = KCV_LENGTH;
    PRUint8    *KCV                   = NULL;
    SECItem    *symmetricKey          = NULL;
    SECStatus   rvExtractSymmetricKey = SECFailure;
    SECStatus   rvKCV                 = SECFailure;
    SECStatus   rvSymmetricKeyname    = SECFailure;
    SECStatus   status                = SECFailure;
#if defined(DEBUG)
    PRIntn      firstCount            = 0;
    PRIntn      secondCount           = 0;
    PRIntn      thirdCount            = 0;
    PRIntn      i                     = 0;
    SECItem     hexSymmetricKey;
#endif

    PR_fprintf( PR_STDOUT,
                "Extracting %s key from operational token . . .\n\n",
                symmetricKeyName );

    rvExtractSymmetricKey = PK11_ExtractKeyValue( /* symmetric key */ symKey );
    if( rvExtractSymmetricKey != SECSuccess ) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  Failed to extract the %s key!\n\n",
                    symmetricKeyName );
        goto destroyHexSymmetricKey;
    }

    /* If present, retrieve the raw key data */
    symmetricKey = PK11_GetKeyData( /* symmetric key */  symKey );

#if defined(DEBUG)
    /* For convenience, display the final symmetric key and */
    /* its associated KCV to the user in DEBUG mode ONLY!!! */
    if( symmetricKey != NULL ) {

        /* Create a clean new display buffer for this symmetric key */
        hexSymmetricKey.type = ( SECItemType ) siBuffer;
        hexSymmetricKey.len  = ( ( symmetricKey->len * 2 ) + 1 );
        hexSymmetricKey.data = ( unsigned char * )
                               PORT_ZAlloc( hexSymmetricKey.len );
        if( hexSymmetricKey.data == NULL ) {
            goto destroyHexSymmetricKey;
        }

        /* Convert this symmetric key into hex digits */
        TKS_StringToHex( ( PRUint8 * ) symmetricKey->data,
                         ( PRIntn )    symmetricKey->len,
                         ( PRUint8 * ) hexSymmetricKey.data,
                         ( PRIntn )    hexSymmetricKey.len );

        /* Display this final symmetric key */
        if( ( ( hexSymmetricKey.len - 1 ) % 4 ) != 0 ) {
            /* invalid key length */
            PR_fprintf( PR_STDERR,
                        "ERROR:  Invalid symmetric key length "
                        "of %d bytes!\n\n\n",
                        hexSymmetricKey.len );
            goto destroyHexSymmetricKey;
        } else {
            /* Print appropriate key name */
            PR_fprintf( PR_STDOUT,
                        "\n    %s key:      ",
                        symmetricKeyName );

            /* Print first DES_LENGTH bytes */
            if( symmetricKey->len == ( 3 * DES_LENGTH ) ) {
                firstCount = ( ( hexSymmetricKey.len - 1 ) / 3 );
            } else {
                firstCount = ( ( hexSymmetricKey.len - 1 ) / 2 );
            }
            for( i = 0; i < firstCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexSymmetricKey.data[i],
                            hexSymmetricKey.data[i + 1],
                            hexSymmetricKey.data[i + 2],
                            hexSymmetricKey.data[i + 3] );
            }

            /* Print appropriate key padding length */
            PR_fprintf( PR_STDOUT, "\n               " );
            for( i = 0; i < PL_strlen( symmetricKeyName ); i++ ) {
                PR_fprintf( PR_STDOUT, " " );
            }

            /* Print second DES_LENGTH bytes */
            secondCount = firstCount * 2;
            for( i = firstCount; i < secondCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexSymmetricKey.data[i],
                            hexSymmetricKey.data[i + 1],
                            hexSymmetricKey.data[i + 2],
                            hexSymmetricKey.data[i + 3] );
            }

            /* print out last 8 bytes of triple-DES keys */
            if( symmetricKey->len == ( 3 * DES_LENGTH ) ) {
                /* Print appropriate key padding length */
                PR_fprintf( PR_STDOUT, "\n               " );
                for( i = 0; i < PL_strlen( symmetricKeyName ); i++ ) {
                    PR_fprintf( PR_STDOUT, " " );
                }

                /* Print third DES_LENGTH bytes */
                thirdCount = hexSymmetricKey.len;
                for( i = secondCount; i < thirdCount; i += 4 ) {
                    PR_fprintf( PR_STDOUT,
                                "%c%c%c%c ",
                                hexSymmetricKey.data[i],
                                hexSymmetricKey.data[i + 1],
                                hexSymmetricKey.data[i + 2],
                                hexSymmetricKey.data[i + 3] );
                }
            }

            /* Print appropriate vertical spacing */
            PR_fprintf( PR_STDOUT, "\n\n\n" );
        }
  
        /* Compute and display this final symmetric key's KCV */
        rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) symmetricKey->data,
                                          ( PRIntn )    symmetricKey->len,
                                          ( PRUint8 * ) KCV,
                                          ( PRIntn )    KCVLen,
                                                        NULL,
                                                        symmetricKeyName,
                                                        SYMMETRIC_KEY,
                                                        PR_TRUE,
                                                        NULL );
        if( rvKCV != SECSuccess ) {
            PR_fprintf( PR_STDERR,
                        "ERROR:  Failed to compute KCV of this %s key!\n\n",
                        symmetricKeyName );
            goto destroyHexSymmetricKey;
        }
    }
#else
    /* Display the final symmetric key's associated KCV to the user . . . */
    if( symmetricKey != NULL ) {
        /* . . . if and only if this is the transport key!!!   */
        if( PL_strcmp( symmetricKeyName, TRANSPORT_KEY ) == 0 ) {
            /* Compute and display this transport key's KCV */
            rvKCV = TKS_ComputeAndDisplayKCV( ( PRUint8 * ) symmetricKey->data,
                                              ( PRIntn )    symmetricKey->len,
                                              ( PRUint8 * ) KCV,
                                              ( PRIntn )    KCVLen,
                                                            NULL,
                                                            symmetricKeyName,
                                                            TRANSPORT_KEY,
                                                            PR_TRUE,
                                                            NULL );
            if( rvKCV != SECSuccess ) {
                PR_fprintf( PR_STDERR,
                            "ERROR:  Failed to compute KCV of this %s key!\n\n",
                            symmetricKeyName );
                goto destroyHexSymmetricKey;
            }
        }
    }
#endif

    PR_fprintf( PR_STDOUT,
                "Storing %s key on final specified token . . .\n\n",
                symmetricKeyName );

    newSymKey = PK11_MoveSymKey( 
    /* slot          */       slot,
    /* operation     */       operation,
    /* flags         */       flags,
    /* permanence    */       PR_TRUE,
    /* symmetric key */       symKey );
    if( newSymKey == NULL ) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  Failed to store the %s key: %d!\n\n",
                    symmetricKeyName,
                    PR_GetError() );
        goto destroyHexSymmetricKey;
    }
    

    PR_fprintf( PR_STDOUT,
                "Naming %s key \"%s\" . . .\n\n",
                symmetricKeyName,
                keyname );

    rvSymmetricKeyname = PK11_SetSymKeyNickname(
                         /* symmetric key */     newSymKey,
                         /* nickname      */     keyname );
    if( rvSymmetricKeyname != SECSuccess ) {
        PR_fprintf( PR_STDERR,
                    "ERROR:  Failed to name the %s key!\n\n",
                    symmetricKeyName );
        goto destroyHexSymmetricKey;
    }

    status = SECSuccess;


destroyHexSymmetricKey:

#if defined(DEBUG)
    /* Destroy the hex symmetric key */
    if( hexSymmetricKey.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexSymmetricKey.data,
                    hexSymmetricKey.len );
        hexSymmetricKey.data = NULL;
        hexSymmetricKey.len  = 0;
    }
#endif

    return status;
}

