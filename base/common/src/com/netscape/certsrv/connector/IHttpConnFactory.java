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
package com.netscape.certsrv.connector;

import com.netscape.certsrv.base.EBaseException;

/**
 * Maintains a pool of connections to to a Remote Authority.
 * Utilized by the IHttpConnector interface.
 * Multiple threads use this interface to utilize and release
 * the Ldap connection resources. This factory will maintain a
 * list of Http type connections to the remote host.
 * 
 * @version $Revision$, $Date$
 */
public interface IHttpConnFactory {

    /**
     * Request access to a Ldap connection from the pool.
     * 
     * @exception EBaseException if any error occurs, such as a
     * @return Ldap connection object.
     *         connection is not available
     */
    public IHttpConnection getConn()
            throws EBaseException;

    /**
     * Return connection to the factory. mandatory after a getConn().
     * 
     * @param conn Ldap connection object to be returned to the free list of the pool.
     * @exception EBaseException On any failure to return the connection.
     */
    public void returnConn(IHttpConnection conn)
            throws EBaseException;
}
