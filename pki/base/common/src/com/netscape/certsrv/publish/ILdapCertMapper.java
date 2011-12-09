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


import java.security.cert.X509Certificate;
import java.util.Vector;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.ldap.ELdapException;


/** 
 * Interface for mapping a X509 certificate to a LDAP entry. 
 *
 * @version $Revision$ $Date$
 */
public interface ILdapCertMapper extends ILdapPlugin {

    /**
     * Returns implementation name.
     */
    public String getImplName();

    /**
     * Returns the description of this mapper.
     */
    public String getDescription();

    /**
     * Returns the default parameters.
     */
    public Vector getDefaultParams();

    /**
     * Returns the instance parameters.
     */
    public Vector getInstanceParams();

    /**
     * maps a certificate to a LDAP entry.
     * returns dn of the mapped LDAP entry.
     * @param conn the LDAP connection
     * @param cert the certificate to map
     * @param checkForCert whether to check for the presence of the cert
     * @exception ELdapException  Failed to map.
     * @return LdapCertMapResult indicates whether a mapping was successful
     * and whether a certificate was found if checkForCert was true.
     * If checkForCert was not set the hasCert method in LdapCertMapResult
     * should be ignored.
     */
    public LdapCertMapResult map(LDAPConnection conn, 
        X509Certificate cert, boolean checkForCert)
        throws ELdapException;
}
