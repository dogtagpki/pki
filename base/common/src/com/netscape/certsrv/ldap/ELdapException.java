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

/**
 * A class that represents a Ldap exception. Various
 * errors can occur when interacting with a Ldap directory server.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class ELdapException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -4345538974758823452L;
    /**
     * Ldap resource class name.
     */
    private static final String LDAP_RESOURCES = LdapResources.class.getName();

    /**
     * Constructs a Ldap exception.
     * 
     * @param msgFormat Resource Key, if key not present, serves as the message.
     *            <P>
     */
    public ELdapException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a Ldap exception.
     * 
     * @param msgFormat Resource Key, if key not present, serves as the message.
     *            Include a message string parameter for variable content.
     * @param param Message string parameter.
     *            <P>
     */
    public ELdapException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a Ldap exception.
     * 
     * @param msgFormat Resource Key, if key not present, serves as the message.
     * @param e Common exception.
     *            <P>
     */
    public ELdapException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a Ldap exception.
     * 
     * @param msgFormat Resource Key, if key not present, serves as the message.
     * @param params Array of Message string parameters.
     *            <P>
     */
    public ELdapException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Gets the resource bundle name
     * 
     * @return Name of the Ldap Exception resource bundle name.
     *         <p>
     */
    protected String getBundleName() {
        return LDAP_RESOURCES;
    }
}
