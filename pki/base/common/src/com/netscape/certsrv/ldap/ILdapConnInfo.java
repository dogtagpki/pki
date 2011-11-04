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


import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;


/**
 * Class for reading ldap connection information from the config store.
 * Ldap connection info: host name, port number,whether of not it is a secure connection.
 *
 * @version $Revision$, $Date$
 */
public interface ILdapConnInfo {
    public static final String PROP_HOST = "host";
    public static final String PROP_PORT = "port";
    public static final String PROP_SECURE = "secureConn";
    public static final String PROP_PROTOCOL = "version";
    public static final String PROP_FOLLOW_REFERRALS = "followReferrals";
    public static final String PROP_HOST_DEFAULT = "localhost";
    public static final String PROP_PORT_DEFAULT = "389";

    public static final int LDAP_VERSION_2 = 2;
    public static final int LDAP_VERSION_3 = 3;

    /**
     * Initializes an instance from a config store.
     * @param config Configuration store.
     * @exception ELdapException Ldap related error found.
     * @exception EBaseException Other errors and errors with params included in the config store. 
     */
    public void init(IConfigStore config) throws EBaseException, ELdapException;

    /**
     *  Return the name of the Host.
     *
     */

    
    public String getHost();

    /**
     * Return the port number of the host.
     *
     */
    public int getPort();

    /**
     * Return the Ldap version number of the Ldap server.
     */

    public int getVersion();

    /**
     * Return whether or not the connection is secure.
     */
    public boolean getSecure();

    /**
     * Return whether or not the server is to follow referrals
     * to other servers when servicing a query.
     */
    public boolean getFollowReferrals();

}
