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


import com.netscape.certsrv.base.*;
import java.security.cert.*;


/**
 * Class on behalf of the Publishing system that controls an instance of an ILdapConnFactory.
 * Allows a factory to be intialized and grants access
 * to the factory to other interested parties.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
 
public interface ILdapConnModule {

    /**
     * Initialize ldap publishing module with config store.
     * @param owner Entity that is interested in this instance of Publishing.
     * @param config Config store containing the info needed to set up Publishing.
     * @exception ELdapException Due to Ldap error.
     * @exception EBaseException Due to config value errors and all other errors.
     */
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException, ELdapException;

    /**
     * Returns the internal ldap connection factory.
     * This can be useful to get a ldap connection to the
     * ldap publishing directory without having to get it again from the
     * config file. Note that this means sharing a ldap connection pool
     * with the ldap publishing module so be sure to return connections to pool.
     * Use ILdapConnFactory.getConn() to get a Ldap connection to the ldap
     * publishing directory.
     * Use ILdapConnFactory.returnConn() to return the connection.
     *
     * @return Instance of ILdapConnFactory.
     */

    public ILdapConnFactory getLdapConnFactory();

    public  ILdapAuthInfo  getLdapAuthInfo();
}

