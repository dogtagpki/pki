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

import netscape.ldap.LDAPException;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;

/**
 * @author Endi S. Dewata
 */
public class LDAPExceptionConverter {

    public static PKIException toPKIException(LDAPException e) {
        switch (e.getLDAPResultCode()) {
        case LDAPException.ATTRIBUTE_OR_VALUE_EXISTS:
            return new ConflictingOperationException("Attribute or value exists.", e);
        case LDAPException.NO_SUCH_OBJECT:
            return new ResourceNotFoundException("No such object.", e);
        case LDAPException.NO_SUCH_ATTRIBUTE:
            return new ResourceNotFoundException("No such attribute.", e);
        case LDAPException.INVALID_DN_SYNTAX:
            return new BadRequestException("Invalid DN syntax.", e);
        case LDAPException.ENTRY_ALREADY_EXISTS:
            return new ConflictingOperationException("Entry already exists.", e);
        default:
            return new PKIException("LDAP error ("+e.getLDAPResultCode()+"): "+e.getMessage(), e);
        }
    }
}
