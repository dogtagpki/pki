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

#include <stdio.h>
#include "ldap.h"

/* Specify the search criteria here. */
#define HOSTNAME "localhost"
#define PORTNUMBER 389
#define BASEDN "ou=Tokens,dc=mcom,dc=com"
#define SCOPE LDAP_SCOPE_SUBTREE
#define FILTER "(cn=*)"

int
main( int argc, char **argv )
{
  LDAP          *ld;
  LDAPMessage   *result = NULL, *e;
  char          *dn = NULL;
  int           version, rc;
  /* Print out an informational message. */
  printf( "Connecting to host %s at port %d...\n\n", HOSTNAME,
    PORTNUMBER );

  /* STEP 1: Get a handle to an LDAP connection and
    set any session preferences. */
  if ( (ld = ldap_init( HOSTNAME, PORTNUMBER )) == NULL ) {
    perror( "ldap_init" );
    return( 1 );
  }

  /* Use the LDAP_OPT_PROTOCOL_VERSION session preference to specify
    that the client is an LDAPv3 client. */
  version = LDAP_VERSION3;
  ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

  /* STEP 2: Bind to the server.
    In this example, the client binds anonymously to the server
    (no DN or credentials are specified). */
  rc = ldap_simple_bind_s( ld, NULL, NULL );
  if ( rc != LDAP_SUCCESS ) {
    fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc));
    return( 1 );
  }
  
  /* Print out an informational message. */
  printf( "Searching the directory for entries\n"
    " starting from the base DN %s\n"
    " within the scope %d\n"
    " matching the search filter %s...\n\n",
    BASEDN, SCOPE, FILTER );

  /* STEP 3: Perform the LDAP operations.
    In this example, a simple search operation is performed.
    The client iterates through each of the entries returned and
    prints out the DN of each entry. */
  rc = ldap_search_ext_s( ld, BASEDN, SCOPE, FILTER, NULL, 0,
    NULL, NULL, NULL, 0, &result );
  if ( rc != LDAP_SUCCESS ) {
    fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(rc));
    return( 1 );
  }
  for ( e = ldap_first_entry( ld, result ); e != NULL;
   e = ldap_next_entry( ld, e ) ) {
    if ( (dn = ldap_get_dn( ld, e )) != NULL ) {
      printf( "dn: %s\n", dn );
      ldap_memfree( dn );
      dn = NULL;
    }
  }
  if( result != NULL ) {
      ldap_msgfree( result );
      result = NULL;
  }

  /* STEP 4: Disconnect from the server. */
  ldap_unbind( ld );
  return( 0 );
}
