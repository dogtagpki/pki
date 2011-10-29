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

/* returns 0 for success, -1 for failure (EOF encountered) */
static int
UpdateRNG( void )
{
    char           *randbuf;
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

#define FPS PR_fprintf( PR_STDOUT, 
    FPS "\n");
    FPS "A random seed must be generated that will be used in the\n");
    FPS "creation of your key.  One of the easiest ways to create a\n");
    FPS "random seed is to use the timing of keystrokes on a keyboard.\n");
    FPS "\n");
    FPS "To begin, type keys on the keyboard until this progress meter\n");
    FPS "is full.  DO NOT USE THE AUTOREPEAT FUNCTION ON YOUR KEYBOARD!\n");
    FPS "\n");
    FPS "\n");
    FPS "Continue typing until the progress meter is full:\n\n");
    FPS "|                                                            |\r|");

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

    /* Get random noise from keyboard strokes */
    randbuf = ( char * ) PORT_Alloc( RAND_BUF_LENGTH );
    count = 0;
    while( randbuf != NULL && count < NUM_KEYSTROKES+1 ) {
#ifdef VMS
        c = GENERIC_GETCHAR_NOECHO();
#elif XP_UNIX
        c = getc( stdin );
#else
        c = getch();
#endif
        if( c == EOF ) {
            rv = -1;
            break;
        }

        PK11_RandomUpdate(
        /* data            */  randbuf,
        /* length in bytes */  RAND_BUF_LENGTH );

        if( c != randbuf[0] ) {
            randbuf[0] = c;

            FPS "\r|");

            for( i = 0 ;
                 i < count / ( NUM_KEYSTROKES / RAND_BUF_LENGTH ) ;
                 i++ ) {
                FPS "*");
            }

            if( count % ( NUM_KEYSTROKES / RAND_BUF_LENGTH ) == 1 ) {
                FPS "/");
            }

            count++;
        }
    }

    if (randbuf != NULL) free (randbuf); 

    FPS "\n\n");
    FPS "Finished.\n");

    TKS_TypeProceedToContinue();

    FPS "\n");

#undef FPS

#if defined( XP_UNIX ) && !defined( VMS )
    /* set back termio the way it was */
    tio.c_lflag     = orig_lflag;
    tio.c_cc[VMIN]  = orig_cc_min;
    tio.c_cc[VTIME] = orig_cc_time;
    tcsetattr( fd, TCSAFLUSH, &tio );
#endif

    return rv;
}


void
TKS_FileForRNG( char *noise )
{
    char        buf[2048];
    PRFileDesc *fd;
    PRInt32     count;

    fd = PR_OpenFile( noise, PR_RDONLY, 0666 );
    if( !fd ) {
        return;
    }

    do {
        count = PR_Read( fd, buf, sizeof( buf ) );
        if (count > 0) {
            PK11_RandomUpdate( 
            /* data            */  buf,
            /* length in bytes */  count );
        }
    } while( count > 0 );

    PR_Close( fd );
}


SECStatus
TKS_SeedRNG( char *noise )
{
    /* Clear the screen */
    TKS_ClearScreen();

    /* Seed the RNG */
    if( noise ) {
        TKS_FileForRNG( noise );
    } else {
        int rv = UpdateRNG();
        if( rv ) {
            PORT_SetError( PR_END_OF_FILE_ERROR );
            return SECFailure;
        }
    }

    return SECSuccess;
}

