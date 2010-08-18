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


import netscape.ldap.*;
import java.security.cert.*;
import netscape.security.x509.X509CRLImpl;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.ldap.*;


/** 
 * Interface for mapping a CRL to a LDAP entry. 
 *
 * @version $Revision$ $Date$
 */
public interface ILdapCrlMapper {

    /**
     * maps a crl to a LDAP entry.
     * returns dn of the mapped LDAP entry.
     * @param conn the LDAP connection
     * @param crl the CRL to map
     * @param checkForCrl whether to check for the presence of the CRL
     * @exception ELdapException  Failed to map CRL to entry.
     * @return LdapCertMapResult indicates whether a mapping was successful
     * and whether a certificate was found if checkForCert was true.
     * If checkForCert was not set the hasCert method in LdapCertMapResult
     * should be ignored.
     */
    public LdapCertMapResult 
    map(LDAPConnection conn, X509CRLImpl crl, boolean checkForCrl)
        throws ELdapException;

    /**
     * initialize from config store.
     * @param config the configuration store to initialize from.
     * @exception ELdapException Initialization failed due to Ldap error.
     * @exception EBaseException Initialization failed.
     */
    public void init(IConfigStore config)
        throws ELdapException, EBaseException;
}
