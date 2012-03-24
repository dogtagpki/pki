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

static SECStatus
DeleteKey( char       *keyname,
           PK11SymKey *key )
{
    char      *name = NULL;
    SECStatus  rv   = SECFailure;

    name = PK11_GetSymKeyNickname( /* symmetric key */  key );
    if( name == NULL ) {
        name = PORT_Strdup( "< orphaned >" );
    }

    /* Delete this key ONLY if its name is the specified keyname */
    /*                                                           */
    /* NOTE:  If duplicate keys are allowed to be added to an    */
    /*        individual token, this function will delete        */
    /*        EVERY key named by the specified keyname;          */
    /*        therefore, MORE than ONE key may be DELETED from   */
    /*        the specified token!!!                             */
    if( PL_strcmp( keyname, name ) == 0 ) {
        rv = PK11_DeleteTokenSymKey( /* symmetric key */  key );
    }

    PORT_Free( name );

    return rv;
}


SECStatus
TKS_DeleteKeys( char *progName,
                PK11SlotInfo *slot,
                char *keyname,
                secuPWData *pwdata )
{
    int         count        = 0;
    int         keys_deleted = 0;
    PK11SymKey *symKey       = NULL;
    PK11SymKey *nextSymKey   = NULL;
    SECStatus   rvDelete     = SECFailure;
    SECStatus   rv;

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
        rvDelete = DeleteKey( keyname,
                              symKey );
        if( rvDelete != SECFailure ) {
            keys_deleted++;
        }

		nextSymKey = PK11_GetNextSymKey( /* symmetric key */  symKey );
        PK11_FreeSymKey( /* symmetric key */  symKey );
        symKey = nextSymKey;
		
        count++;
    }

    if( keys_deleted == 0 ) {
        PR_fprintf( PR_STDOUT,
                    "\t%s: no key(s) called \"%s\" could be deleted\n",
                    progName,
                    keyname );

        rv = SECFailure;
    } else {
        PR_fprintf( PR_STDOUT,
                    "%s: %d key(s) called \"%s\" were deleted\n",
                    progName,
                    keys_deleted,
                    keyname );

        rv = SECSuccess;
    }

    return rv;
}

