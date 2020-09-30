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

/*
 *  L i s t S e c M o d u l e s
 *
 *  Print a list of the PKCS11 security modules that are
 *  available. This is useful for smartcard people to
 *  make sure they have the drivers loaded.
 *
 */
SECStatus
TKS_ListSecModules( void )
{
    PK11SlotList        *list;
    PK11SlotListElement *le;

    /* get them all! */
    list = PK11_GetAllTokens( 
    /* mechanism type */      CKM_INVALID_MECHANISM,
    /* need R/W       */      PR_FALSE,
    /* load certs     */      PR_FALSE,
    /* wincx          */      NULL );

    if( list == NULL ) {
        return SECFailure;
    }

    /* look at each slot */
    for( le = list->head ; le ; le = le->next ) {
        PR_fprintf ( PR_STDOUT,
                     "\n" );
        PR_fprintf ( PR_STDOUT,
                     "    slot: %s\n",
                     PK11_GetSlotName( /* slot */  le->slot ) );
        PR_fprintf ( PR_STDOUT,
                     "   token: %s\n",
                     PK11_GetTokenName( /* slot */  le->slot ) );
    }

    PK11_FreeSlotList( /* slot list */  list );

    return SECSuccess;
}

