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
package com.netscape.certsrv.publish;

import java.util.Vector;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.request.IRequest;

/**
 * Interface for mapping a X509 certificate to a LDAP entry.
 * 
 * @version $Revision$ $Date$
 */
public interface ILdapMapper extends ILdapPlugin {

    /**
     * Returns implementation name.
     */
    public String getImplName();

    /**
     * Returns the description of this mapper.
     */
    public String getDescription();

    /**
     * Returns the initial default parameters.
     */
    public Vector<String> getDefaultParams();

    /**
     * Returns the current instance parameters.
     */
    public Vector<String> getInstanceParams();

    /**
     * maps a certificate to a LDAP entry.
     * returns dn of the mapped LDAP entry.
     * 
     * @param conn the LDAP connection
     * @param obj the object to map
     * @return dn indicates whether a mapping was successful
     * @exception ELdapException Map operation failed.
     */
    public String
            map(LDAPConnection conn, Object obj)
                    throws ELdapException;

    /**
     * maps a certificate to a LDAP entry.
     * returns dn of the mapped LDAP entry.
     * 
     * @param conn the LDAP connection
     * @param r the request to map
     * @param obj the object to map
     * @return dn indicates whether a mapping was successful
     * @exception ELdapException Map operation failed.
     */
    public String
            map(LDAPConnection conn, IRequest r, Object obj)
                    throws ELdapException;
}
