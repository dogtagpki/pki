// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.ldap;

/**
 * Maintains a pool of connections to the LDAP server. CMS requests are
 * processed on a multi threaded basis. A pool of connections then must be be
 * maintained so this access to the Ldap server can be easily managed. The min
 * and max size of this connection pool should be configurable. Once the maximum
 * limit of connections is exceeded, the factory should provide proper
 * synchronization to resolve contention issues.
 * 
 * @version $Revision$, $Date$
 */
public interface ILdapBoundConnFactory extends ILdapConnFactory {

    public static final String PROP_MINCONNS = "minConns";
    public static final String PROP_MAXCONNS = "maxConns";
    public static final String PROP_LDAPCONNINFO = "ldapconn";
    public static final String PROP_LDAPAUTHINFO = "ldapauth";

}
