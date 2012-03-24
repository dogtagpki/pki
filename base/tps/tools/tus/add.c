/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

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

#include "nsapi.h"

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "ldap.h"

#include "tus/tus_db.h"

/* Specify the search criteria here. */
static char *host = "localhost";
static int  port = 389;
static char *baseDN    = "ou=Tokens,dc=mcom,dc=com";
static char *prefix = "0000";
static char *suffix = "0000";
static int  start = 1;
static int  len = 0;
static char *who = NULL;
static char *password = NULL;
static char *token_type = NULL;


#define SCOPE LDAP_SCOPE_SUBTREE
#define FILTER "(cn=*)"

int main (int argc, char **argv)
{
    int           i, h, rc;
    char cn[256];
    char *errorMsg = NULL;

    if (argc < 9 || argc > 11) {
        printf ("Usage:\n  %s baseDN prefix suffix start len who password token_type host port", argv[0]);
        return 1;
    }

    baseDN = argv[1];
    prefix = argv[2];
    suffix = argv[3];
    start = atoi(argv[4]);
    len = atoi(argv[5]);
    who = argv[6];
    password = argv[7];
    token_type = argv[8];

    if (argc > 9) {
        host = argv[9];
    }

    if (argc > 10) {
        port = atoi(argv[10]);
    }

    set_tus_db_baseDN(baseDN);
    set_tus_db_port(port);
    set_tus_db_host(host);
    set_tus_db_bindDN(who);
    set_tus_db_bindPass(password);
    rc = tus_db_init(errorMsg);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "tus_db_init: (%d) %s\n", rc, errorMsg);
        return 1;
    }

    for (i = 0; i < len; i++) {
        h = start + i;
        sprintf(cn, "%s%08X%s", prefix, h, suffix);
        printf ("Adding %s\n", cn);

        rc = add_default_tus_db_entry (NULL, "", cn, "active", "", "", token_type);
        if (rc != LDAP_SUCCESS) {
            fprintf( stderr, "ldap_add_ext_s: %s\n", ldap_err2string( rc ) );
            return 1;
        }
    }
    
    /* STEP 4: Disconnect from the server. */
    tus_db_end();

    return( 0 );
}
