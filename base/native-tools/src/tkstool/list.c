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

/* callback for listing keys through pkcs11 */
static SECStatus
PrintSymKey( struct PRFileDesc *out,
                  int                count,
                  char              *keyname,
                  PK11SymKey        *key )
{
    char      *name = NULL;
    SECStatus  rv   = SECFailure;

    name = PK11_GetSymKeyNickname( /* symmetric key */  key );
    if( name == NULL ) {
        name = PORT_Strdup( "\t< orphaned >" );
    }

    if( keyname != NULL ) {
        /* ONLY print this name if it is the requested key */
        if( PL_strcmp( keyname, name ) == 0 ) {
            PR_fprintf( out,
                        "\t<%d> %s\n",
                        count,
                        name );

            rv = SECSuccess;
        }
    } else {
        PR_fprintf( out,
                    "\t<%d> %s\n",
                    count,
                    name );

        rv = SECSuccess;
    }

    PORT_Free( name );

    return rv;
}


static SECStatus
listKeys( char *progName,
          PK11SlotInfo *slot,
          char *keyname,
          void *pwdata )
{
    int         count      = 0;
    int         keys_found = 0;
    PK11SymKey *symKey     = NULL;
    PK11SymKey *nextSymKey = NULL;
    SECStatus   rvPrint    = SECFailure;

    if( PK11_NeedLogin( /* slot */  slot ) ) {
        PK11_Authenticate( 
        /* slot       */   slot,
        /* load certs */   PR_TRUE,
        /* wincx      */   pwdata );
    }

    /* Initialize the symmetric key list. */
    symKey = PK11_ListFixedKeysInSlot( 
             /* slot     */            slot,
             /* nickname */            NULL,
             /* wincx    */            ( void *) pwdata );

    /* Iterate through the symmetric key list. */
	while( symKey != NULL ) {
        rvPrint = PrintSymKey( PR_STDOUT,
                               count,
                               keyname,
                               symKey );
        if( rvPrint != SECFailure ) {
            keys_found++;
        }

		nextSymKey = PK11_GetNextSymKey( /* symmetric key */  symKey );
        PK11_FreeSymKey( /* symmetric key */  symKey );
        symKey = nextSymKey;
		
        count++;
    }

    /* case 1:  the token is empty */
    if( count == 0 ) {
        PR_fprintf( PR_STDOUT,
                    "\t%s: the specified token is empty\n",
                    progName );

        return SECFailure;
    }

    /* case 2:  the specified key is not on this token */
    if( ( keyname != NULL ) &&
        ( keys_found == 0 ) ) {
        PR_fprintf( PR_STDOUT,
                    "\t%s: the key called \"%s\" could not be found\n",
                    progName,
                    keyname );

        return SECFailure;
    }

    return SECSuccess;
}


SECStatus
TKS_ListKeys( char *progName,
              PK11SlotInfo *slot,
              char *keyname,
              int index, 
              PRBool dopriv,
              secuPWData *pwdata )
{
    SECStatus rv = SECSuccess;

    if( slot == NULL ) {
        PK11SlotList        *list;
        PK11SlotListElement *le;

        list = PK11_GetAllTokens( 
        /* mechanism type */      CKM_INVALID_MECHANISM,
        /* need R/W       */      PR_FALSE,
        /* load certs     */      PR_FALSE,
        /* wincx          */      pwdata );

        if( list ) {
            for( le = list->head ; le ; le = le->next ) {
                PR_fprintf( PR_STDOUT,
                            "\n slot:  %s\n",
                            PK11_GetSlotName( /* slot */  le->slot ) );

                PR_fprintf( PR_STDOUT,
                            "token:  %s\n\n",
                            PK11_GetTokenName( /* slot */  le->slot ) );

                rv = listKeys( progName,
                               le->slot,
                               keyname,
                               pwdata );
            }
        }
    } else {
        PR_fprintf( PR_STDOUT,
                    "\n slot:  %s\n",
                    PK11_GetSlotName( /* slot */  slot ) );

        PR_fprintf( PR_STDOUT,
                    "token:  %s\n\n",
                    PK11_GetTokenName( /* slot */  slot ) );

        rv = listKeys( progName,
                       slot,
                       keyname,
                       pwdata );
    }

    return rv;
}

