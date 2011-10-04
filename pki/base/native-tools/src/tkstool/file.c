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

SECStatus
TKS_ReadInputFileIntoSECItem( char    *input,
                              char    *hexInternalKeyKCV,
                              int      hexInternalKeyKCVLength,
                              char    *wrappedKeyName,
                              SECItem *wrappedKey )
{
    char        buf[1];
    PRFileDesc *fd               = NULL;
    PRInt32     c                = 0;
    PRInt32     k                = 0;
    PRInt32     count            = 0;
    PRIntn      firstCount       = 0;
    PRIntn      secondCount      = 0;
    PRIntn      thirdCount       = 0;
    PRIntn      i                = 0;
    SECItem     hexWrappedKey    = { siBuffer,
                                     NULL,
                                     0 };
    SECStatus   status           = SECFailure;

    /* Create a clean new hex display buffer for this wrapped key */
    hexWrappedKey.type = ( SECItemType ) siBuffer;
    hexWrappedKey.len  = ( ( wrappedKey->len * 2 ) + 1 );
    hexWrappedKey.data = ( unsigned char * )
                         PORT_ZAlloc( hexWrappedKey.len );
    if( hexWrappedKey.data == NULL ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* open the input file read-only */
    fd = PR_OpenFile( input, PR_RDONLY, 0666 );
    if( !fd ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* read in the wrapped key */
    while( c < HEX_WRAPPED_KEY_LENGTH ) {
        /* read in the next byte */
        count = PR_Read( fd, buf, 1 );

        /* check for EOF */
        if( count > 0 ) {
            /* save acceptable hex characters    */
            /* silently throw anything else away */
            switch( *buf ) {
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
                    hexWrappedKey.data[c] = buf[0];
                    break;
                case 'A':
                case 'a':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'A';
                    break;
                case 'B':
                case 'b':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'B';
                    break;
                case 'C':
                case 'c':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'C';
                    break;
                case 'D':
                case 'd':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'D';
                    break;
                case 'E':
                case 'e':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'E';
                    break;
                case 'F':
                case 'f':
                    /* acceptable character; save uppercase version */
                    hexWrappedKey.data[c] = 'F';
                    break;
                default:
                    /* unacceptable character; don't save it */
                    continue;
            }

            /* increment the number of wrapped key bytes read */
            c++;
        }
    }

    /* insure that the wrapped key was completely obtained */
    if( c != HEX_WRAPPED_KEY_LENGTH ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* Convert these wrapped key hex digits */
    /* into the data portion of a SECItem   */
    TKS_ConvertStringOfHexCharactersIntoBitStream( ( char * ) hexWrappedKey.data,
                                                   ( hexWrappedKey.len - 1 ),
                                                   wrappedKey->data );

    /* read in the wrapped key KCV */
    while( k < HEX_WRAPPED_KEY_KCV_LENGTH ) {
        count = PR_Read( fd, buf, 1 );

        if( count > 0 ) {
            /* save acceptable hex characters; silently */
            /* throw anything else away                 */
            switch( *buf ) {
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
                    hexInternalKeyKCV[k] = buf[0];
                    break;
                case 'A':
                case 'a':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'A';
                    break;
                case 'B':
                case 'b':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'B';
                    break;
                case 'C':
                case 'c':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'C';
                    break;
                case 'D':
                case 'd':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'D';
                    break;
                case 'E':
                case 'e':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'E';
                    break;
                case 'F':
                case 'f':
                    /* acceptable character; save uppercase version */
                    hexInternalKeyKCV[k] = 'F';
                    break;
                default:
                    /* unacceptable character; don't save it */
                    continue;
            }

            /* increment the number of key KCV bytes read */
            k++;
        }
    }

    /* insure that the wrapped key KCV was completely obtained */
    if( k != HEX_WRAPPED_KEY_KCV_LENGTH ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* For convenience, display the read-in wrapped key */
    /* and its associated KCV to the user.              */
    if( hexWrappedKey.data != NULL ) {
        /* Display this final wrapped key */
        if( ( hexWrappedKey.len - 1 ) !=
            HEX_WRAPPED_KEY_LENGTH ) {
            /* invalid key length */
            PR_fprintf( PR_STDERR,
                        "ERROR:  Invalid data length of %d bytes!\n\n\n",
                        hexWrappedKey.len );
            status = SECFailure;
            goto destroyHexWrappedKey;
        } else {
            /* Print wrapped data blob */
            PR_fprintf( PR_STDOUT,
                        "\n    wrapped data:    " );

            /* Print first DES_LENGTH bytes */
            if( wrappedKey->len == ( 3 * DES_LENGTH ) ) {
                firstCount = ( ( hexWrappedKey.len - 1 ) / 3 );
            } else {
                firstCount = ( ( hexWrappedKey.len - 1 ) / 2 );
            }
            for( i = 0; i < firstCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexWrappedKey.data[i],
                            hexWrappedKey.data[i + 1],
                            hexWrappedKey.data[i + 2],
                            hexWrappedKey.data[i + 3] );
            }

            /* Print appropriate padding length */
            PR_fprintf( PR_STDOUT, "\n                     " );

            /* Print second DES_LENGTH bytes */
            secondCount = firstCount * 2;
            for( i = firstCount; i < secondCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexWrappedKey.data[i],
                            hexWrappedKey.data[i + 1],
                            hexWrappedKey.data[i + 2],
                            hexWrappedKey.data[i + 3] );
            }

            /* print out last 8 bytes of triple-DES keys */
            if( wrappedKey->len == ( 3 * DES_LENGTH ) ) {
                /* Print appropriate padding length */
                PR_fprintf( PR_STDOUT, "\n                     " );

                /* Print third DES_LENGTH bytes */
                thirdCount = hexWrappedKey.len;
                for( i = secondCount; i < thirdCount; i += 4 ) {
                    PR_fprintf( PR_STDOUT,
                                "%c%c%c%c ",
                                hexWrappedKey.data[i],
                                hexWrappedKey.data[i + 1],
                                hexWrappedKey.data[i + 2],
                                hexWrappedKey.data[i + 3] );
                }
            }

            /* Print appropriate vertical spacing */
            PR_fprintf( PR_STDOUT, "\n\n\n" );
        }
    }
  
    if( hexInternalKeyKCV != NULL ) {
        /* Display this final wrapped key's KCV */
        if( ( hexInternalKeyKCVLength - 1 ) !=
            HEX_WRAPPED_KEY_KCV_LENGTH ) {
            /* invalid key length */
            PR_fprintf( PR_STDERR,
                        "ERROR:  Invalid key KCV length "
                        "of %d bytes!\n\n\n",
                        hexInternalKeyKCVLength );
            status = SECFailure;
            goto destroyHexWrappedKey;
        } else {
            PR_fprintf( PR_STDOUT,
                        "    master key KCV:  "
                        "%c%c%c%c %c%c%c%c\n    (pre-computed KCV of the "
                        "master key residing inside the wrapped data)\n\n\n",
                        hexInternalKeyKCV[0],
                        hexInternalKeyKCV[1],
                        hexInternalKeyKCV[2],
                        hexInternalKeyKCV[3],
                        hexInternalKeyKCV[4],
                        hexInternalKeyKCV[5],
                        hexInternalKeyKCV[6],
                        hexInternalKeyKCV[7] );
        }
    }

    /* close the input file */
    PR_Close( fd );

    status = SECSuccess;

destroyHexWrappedKey:
    /* Destroy the hex wrapped key */
    if( hexWrappedKey.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexWrappedKey.data,
                    hexWrappedKey.len );
        hexWrappedKey.data = NULL;
        hexWrappedKey.len  = 0;
    }

    return status;
}


SECStatus
TKS_WriteSECItemIntoOutputFile( SECItem *wrappedKey,
                                char    *wrappedKeyName,
                                char    *hexInternalKeyKCV,
                                int      hexInternalKeyKCVLength,
                                char    *output )
{
    PRFileDesc *fd               = NULL;
    PRInt32     count            = 0;
    PRInt32     r                = 0;
    PRIntn      firstCount       = 0;
    PRIntn      secondCount      = 0;
    PRIntn      thirdCount       = 0;
    PRIntn      i                = 0;
    SECItem     hexWrappedKey    = { siBuffer,
                                     NULL,
                                     0 };
    SECStatus   status           = SECFailure;

    /* Create a clean new hex display buffer for this wrapped key */
    hexWrappedKey.type = ( SECItemType ) siBuffer;
    hexWrappedKey.len  = ( ( wrappedKey->len * 2 ) + 1 );
    hexWrappedKey.data = ( unsigned char * )
                         PORT_ZAlloc( hexWrappedKey.len );
    if( hexWrappedKey.data == NULL ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* Convert this wrapped key into hex digits */
    TKS_StringToHex( ( PRUint8 * ) wrappedKey->data,
                     ( PRIntn )    wrappedKey->len,
                     ( PRUint8 * ) hexWrappedKey.data,
                     ( PRIntn )    hexWrappedKey.len );

    /* For convenience, display this wrapped key to the user. */
    if( hexWrappedKey.data != NULL ) {
        /* Display this final wrapped key */
        if( ( hexWrappedKey.len - 1 ) !=
            HEX_WRAPPED_KEY_LENGTH ) {
            /* invalid key length */
            PR_fprintf( PR_STDERR,
                        "ERROR:  Invalid data length of %d bytes!\n\n\n",
                        hexWrappedKey.len );
            status = SECFailure;
            goto destroyHexWrappedKey;
        } else {
            /* Print wrapped data blob */
            PR_fprintf( PR_STDOUT,
                        "    wrapped data:    " );

            /* Print first DES_LENGTH bytes */
            if( wrappedKey->len == ( 3 * DES_LENGTH ) ) {
                firstCount = ( ( hexWrappedKey.len - 1 ) / 3 );
            } else {
                firstCount = ( ( hexWrappedKey.len - 1 ) / 2 );
            }
            for( i = 0; i < firstCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexWrappedKey.data[i],
                            hexWrappedKey.data[i + 1],
                            hexWrappedKey.data[i + 2],
                            hexWrappedKey.data[i + 3] );
            }

            /* Print appropriate padding length */
            PR_fprintf( PR_STDOUT, "\n                     " );

            /* Print second DES_LENGTH bytes */
            secondCount = firstCount * 2;
            for( i = firstCount; i < secondCount; i += 4 ) {
                PR_fprintf( PR_STDOUT,
                            "%c%c%c%c ",
                            hexWrappedKey.data[i],
                            hexWrappedKey.data[i + 1],
                            hexWrappedKey.data[i + 2],
                            hexWrappedKey.data[i + 3] );
            }

            /* print out last 8 bytes of triple-DES keys */
            if( wrappedKey->len == ( 3 * DES_LENGTH ) ) {
                /* Print appropriate padding length */
                PR_fprintf( PR_STDOUT, "\n                     " );

                /* Print third DES_LENGTH bytes */
                thirdCount = hexWrappedKey.len;
                for( i = secondCount; i < thirdCount; i += 4 ) {
                    PR_fprintf( PR_STDOUT,
                                "%c%c%c%c ",
                                hexWrappedKey.data[i],
                                hexWrappedKey.data[i + 1],
                                hexWrappedKey.data[i + 2],
                                hexWrappedKey.data[i + 3] );
                }
            }

            /* Print appropriate vertical spacing */
            PR_fprintf( PR_STDOUT, "\n\n\n" );
        }
    }

    /* For convenience, display this wrapped key's */
    /* master key KCV to the user.                 */
    if( ( hexInternalKeyKCV != NULL ) &&
        ( hexInternalKeyKCVLength == HEX_WRAPPED_KEY_KCV_LENGTH ) ) {
            /* display this wrapped key's computed KCV value (in hex) */
            PR_fprintf( PR_STDOUT,
                        "    master key KCV:  "
                        "%c%c%c%c %c%c%c%c\n    (computed KCV of the "
                        "master key residing inside the wrapped data)\n\n\n",
                        hexInternalKeyKCV[0],
                        hexInternalKeyKCV[1],
                        hexInternalKeyKCV[2],
                        hexInternalKeyKCV[3],
                        hexInternalKeyKCV[4],
                        hexInternalKeyKCV[5],
                        hexInternalKeyKCV[6],
                        hexInternalKeyKCV[7] );
    }

    /* open the output file read-write */
    fd = PR_OpenFile( output, ( PR_RDWR | PR_CREATE_FILE ), 0666 );
    if( !fd ) {
        status = SECFailure;
        goto destroyHexWrappedKey;
    }

    /* write out the wrapped key (in hex) to the output file */
    while( count < HEX_WRAPPED_KEY_LENGTH ) {
        /* write out 4 bytes */
        r = PR_Write( fd, &( hexWrappedKey.data[count] ), 4 );
        if( r != 4 ) {
            status = SECFailure;
            goto destroyHexWrappedKey;
        }

        /* increment the byte count by 4 */
        count += 4;

        if( count >= HEX_WRAPPED_KEY_LENGTH ) {
            r = PR_Write( fd, "\n", 1 );
            if( r != 1 ) {
                status = SECFailure;
                goto destroyHexWrappedKey;
            }
        } else {
            r = PR_Write( fd, " ", 1 );
            if( r != 1 ) {
                status = SECFailure;
                goto destroyHexWrappedKey;
            }
        }
    }

    /* reinitialize count */
    count = 0;

    /* write out the master key KCV (in hex) to the output file */
    while( count < HEX_WRAPPED_KEY_KCV_LENGTH ) {
        /* write out 4 bytes */
        r = PR_Write( fd, &( hexInternalKeyKCV[count] ), 4 );
        if( r != 4 ) {
            status = SECFailure;
            goto destroyHexWrappedKey;
        }

        /* increment the byte count by 4 */
        count += 4;

        if( count >= HEX_WRAPPED_KEY_KCV_LENGTH ) {
            r = PR_Write( fd, "\n", 1 );
            if( r != 1 ) {
                status = SECFailure;
                goto destroyHexWrappedKey;
            }
        } else {
            r = PR_Write( fd, " ", 1 );
            if( r != 1 ) {
                status = SECFailure;
                goto destroyHexWrappedKey;
            }
        }
    }

    /* close the output file */
    PR_Close( fd );

    status = SECSuccess;

destroyHexWrappedKey:
    /* Destroy the hex wrapped key */
    if( hexWrappedKey.data != NULL ) {
        PORT_ZFree( ( unsigned char * )
                    hexWrappedKey.data,
                    hexWrappedKey.len );
        hexWrappedKey.data = NULL;
        hexWrappedKey.len  = 0;
    }

    return status;
}

