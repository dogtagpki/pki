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

static PRBool
IsValidHexCharacter( char byte )
{
    switch( byte )
    {
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
        case 'a':
        case 'A':
        case 'b':
        case 'B':
        case 'c':
        case 'C':
        case 'd':
        case 'D':
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        {
            /* Character may be converted into a hexadecimal number. */
            return PR_TRUE;
        }
        default:
        {
            return PR_FALSE;
        }
    }
}


static void
InsertUpperFourBits( char* byte, char bits )
{
    switch( bits )
    {
        case '0':
        {
            *byte &= ~( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case '1':
        {
            *byte &= ~( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case '2':
        {
            *byte &= ~( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case '3':
        {
            *byte &= ~( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case '4':
        {
            *byte &= ~( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case '5':
        {
            *byte &= ~( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case '6':
        {
            *byte &= ~( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case '7':
        {
            *byte &= ~( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case '8':
        {
            *byte |= ( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case '9':
        {
            *byte |= ( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case 'a':
        case 'A':
        {
            *byte |= ( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case 'b':
        case 'B':
        {
            *byte |= ( 1 << 7 );
            *byte &= ~( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case 'c':
        case 'C':
        {
            *byte |= ( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case 'd':
        case 'D':
        {
            *byte |= ( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte &= ~( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
        case 'e':
        case 'E':
        {
            *byte |= ( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte &= ~( 1 << 4 );
            break;
        }
        case 'f':
        case 'F':
        {
            *byte |= ( 1 << 7 );
            *byte |= ( 1 << 6 );
            *byte |= ( 1 << 5 );
            *byte |= ( 1 << 4 );
            break;
        }
    }
}


static void
InsertLowerFourBits( char* byte, char bits )
{
    switch( bits )
    {
        case '0':
        {
            *byte &= ~( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case '1':
        {
            *byte &= ~( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case '2':
        {
            *byte &= ~( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case '3':
        {
            *byte &= ~( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case '4':
        {
            *byte &= ~( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case '5':
        {
            *byte &= ~( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case '6':
        {
            *byte &= ~( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case '7':
        {
            *byte &= ~( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case '8':
        {
            *byte |= ( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case '9':
        {
            *byte |= ( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case 'a':
        case 'A':
        {
            *byte |= ( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case 'b':
        case 'B':
        {
            *byte |= ( 1 << 3 );
            *byte &= ~( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case 'c':
        case 'C':
        {
            *byte |= ( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case 'd':
        case 'D':
        {
            *byte |= ( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte &= ~( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
        case 'e':
        case 'E':
        {
            *byte |= ( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte &= ~( 1 << 0 );
            break;
        }
        case 'f':
        case 'F':
        {
            *byte |= ( 1 << 3 );
            *byte |= ( 1 << 2 );
            *byte |= ( 1 << 1 );
            *byte |= ( 1 << 0 );
            break;
        }
    }
}


PR_IMPLEMENT( void )
TKS_ClearScreen()
{
#if defined(XP_UNIX) && !defined(VMS)
    system( "tput clear" );
#else
    system( "cls" );
#endif
}


PR_IMPLEMENT( void )
TKS_WaitForUser()
{
    int            c;

    PR_fprintf( PR_STDOUT, "\n\n" );
    PR_fprintf( PR_STDOUT, "%s", CONTINUATION_MESSAGE );
#if defined(VMS)
    while((c = GENERIC_GETCHAR_NO_ECHO()) != '\r' && c != EOF && c != CTRL_C )
    ;
#else
    while ((c = getc(stdin)) != '\n' && c != EOF && c != CTRL_C )
    ;
#endif
    PR_fprintf( PR_STDOUT, "\n" );
}


PR_IMPLEMENT( void )
TKS_TypeProceedToContinue()
{
    int            fd;
    int            i;
    int            count;
    int            c;
    int            rv = 0;
#ifdef XP_UNIX
    cc_t           orig_cc_min;
    cc_t           orig_cc_time;
    tcflag_t       orig_lflag;
    struct termios tio;
#endif
    char           keystrokes[KEYSTROKES_TO_PROCEED + 1] = "\0\0\0\0\0\0\0\0\0";

    /* display the continuation message */
    PR_fprintf( PR_STDOUT, "\n\n" );
    PR_fprintf( PR_STDOUT, "%s", PROCEED_MESSAGE );

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
    while( count < KEYSTROKES_TO_PROCEED ) {
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

        /* save acceptable characters; silently throw anything else away */
        switch( count ) {
            case 0:
                switch( c ) {
                    case 'P':
                    case 'p':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'p';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 1:
                switch( c ) {
                    case 'R':
                    case 'r':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'r';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 2:
                switch( c ) {
                    case 'O':
                    case 'o':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'o';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 3:
                switch( c ) {
                    case 'C':
                    case 'c':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'c';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 4:
                switch( c ) {
                    case 'E':
                    case 'e':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'e';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 5:
                switch( c ) {
                    case 'E':
                    case 'e':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'e';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 6:
                switch( c ) {
                    case 'D':
                    case 'd':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = 'd';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            case 7:
                switch( c ) {
                    case '\n':
                    case '\r':
                        /* acceptable character; save lowercase version */
                        keystrokes[count] = '\n';
                        break;
                    default:
                        /* unacceptable character; don't save it */
                        continue;
                }
                break;
            default:
                /* unacceptable character; don't save it */
                continue;
        }

        /* adjust the character count appropriately */
        count++;

        /* redisplay the message */
        PR_fprintf( PR_STDOUT, "\r%s", PROCEED_MESSAGE );

        /* display the characters input so far */
        for( i = 0 ; i < count ; i++ ) {
            PR_fprintf( PR_STDOUT,
                        "%c",
                        keystrokes[i] );
        }
    }
}


PR_IMPLEMENT( void )
TKS_AdjustOddParity( PRUint8 *key )
{
    PRIntn i;
    PRIntn j;
    PRIntn one;

    /* this must be performed for each DES-sized (8-byte) chunk */
    for( j = 0 ; j < DES_LENGTH ; j++ ) {
        for( one = 0, i = key[j] ; i ; i >>= 1 ) {
            if( i & 1 ) {
                one++;
            }
        }

        key[j] ^= !( one & 1 );
    }
}


PR_IMPLEMENT( void )
TKS_StringToHex( PRUint8 *key,
                 PRIntn len,
                 PRUint8 *hex_key,
                 PRIntn hex_len )
{
    PRIntn        i;

    for( i = 0 ; i < len ; i++ ) {
        ( void ) PR_snprintf( ( char * ) &( hex_key[ ( 2 * i ) ] ),
                              hex_len,
                              "%X",
                              ( key[i] >> 4 ) & 0x0F );
        ( void ) PR_snprintf( ( char * ) &( hex_key[ ( 2 * i ) + 1 ] ),
                              hex_len,
                              "%X",
                              key[i] & 0x0F );
    }

    hex_key[ ( hex_len - 1 ) ] = '\0';

    return;
}


/* Convert a signed character string such as "de43a58f. . ." into an */
/* unsigned character string which is one/half the size of the input */
PR_IMPLEMENT( PRBool )
TKS_ConvertStringOfHexCharactersIntoBitStream( char* input,
                                               PRIntn input_bytes,
                                               PRUint8* output )
{
    PRIntn i;
    PRIntn output_bytes;

    /* Check to be sure that the input string contains an  */
    /* "even" number of bytes so that it may be converted. */
    if( input_bytes % 2 ) {
        ( void ) PR_fprintf( PR_STDERR,
                             "ERROR:  "
                             "ConvertStringOfHexCharactersIntoBitStream() "
                             "contained an illegal "
                             "input byte length of %d bytes!\r\n",
                             input_bytes );
        return PR_FALSE;
    }

    output_bytes = ( input_bytes / 2 );

    for( i = 0; i < output_bytes; i++ ) {
        if( IsValidHexCharacter( input[ ( 2 * i ) ] ) &&
            IsValidHexCharacter( input[ ( 2 * i ) + 1 ] ) ) {
        InsertUpperFourBits( ( char* ) &( output[i] ), input[ ( 2 * i ) ] );
        InsertLowerFourBits( ( char* ) &( output[i] ), input[ ( 2 * i ) + 1 ] );
        } else {
            ( void ) PR_fprintf( PR_STDERR,
                                 "ERROR:  "
                                 "ConvertStringOfHexCharactersIntoBitStream() "
                                 "contained a "
                                 "byte in the input string which can not be "
                                 "converted!\r\n" );
            return PR_FALSE;
        }
    }

   return PR_TRUE;
}


