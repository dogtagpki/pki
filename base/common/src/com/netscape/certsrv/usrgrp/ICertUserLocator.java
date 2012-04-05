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
package com.netscape.certsrv.usrgrp;

import netscape.ldap.LDAPException;

import com.netscape.certsrv.ldap.ELdapException;

/**
 * This interface defines a certificate mapping strategy to locate
 * a user
 *
 * @version $Revision$, $Date$
 */
public interface ICertUserLocator {

    /**
     * Returns a user whose certificates match with the given certificates
     *
     * @return an user interface
     * @exception EUsrGrpException thrown when failed to build user
     * @exception LDAPException thrown when LDAP internal database is not available
     * @exception ELdapException thrown when the LDAP search failed
     */
    public IUser locateUser(Certificates certs) throws
            EUsrGrpException, LDAPException, ELdapException;

    /**
     * Retrieves description.
     *
     * @return description
     */
    public String getDescription();
}
