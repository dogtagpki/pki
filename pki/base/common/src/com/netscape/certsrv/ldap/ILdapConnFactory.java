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

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * Maintains a pool of connections to the LDAP server.
 * Multiple threads use this interface to utilize and release
 * the Ldap connection resources.
 * 
 * @version $Revision$, $Date$
 */
public interface ILdapConnFactory {

    /**
     * Initialize the poll from the config store.
     * 
     * @param config The configuration substore.
     * @exception EBaseException On configuration error.
     * @exception ELdapException On all other errors.
     */
    public void init(IConfigStore config)
            throws EBaseException, ELdapException;

    /**
     * 
     * Used for disconnecting all connections.
     * Used just before a subsystem
     * shutdown or process exit.
     * 
     * @exception EldapException on Ldap failure when closing connections.
     */
    public void reset()
            throws ELdapException;

    /**
     * Returns the number of free connections available from this pool.
     * 
     * @return Integer number of free connections.
     */

    public int freeConn();

    /**
     * Returns the number of total connections available from this pool.
     * Includes sum of free and in use connections.
     * 
     * @return Integer number of total connections.
     */
    public int totalConn();

    /**
     * Returns the maximum number of connections available from this pool.
     * 
     * @return Integer maximum number of connections.
     */
    public int maxConn();

    /**
     * Request access to a Ldap connection from the pool.
     * 
     * @exception ELdapException if any error occurs, such as a
     * @return Ldap connection object.
     *         connection is not available
     */
    public LDAPConnection getConn()
            throws ELdapException;

    /**
     * Return connection to the factory. mandatory after a getConn().
     * 
     * @param conn Ldap connection object to be returned to the free list of the pool.
     * @exception ELdapException On any failure to return the connection.
     */
    public void returnConn(LDAPConnection conn)
            throws ELdapException;

}
