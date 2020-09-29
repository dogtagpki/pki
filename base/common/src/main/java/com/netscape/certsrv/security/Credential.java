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
package com.netscape.certsrv.security;

/**
 * A class represents a credential. A credential contains
 * information that identifies a user. In this case,
 * identifier and password are used.
 *
 * @version $Revision$, $Date$
 */
public class Credential implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7810193228062824943L;
    private String mId = null;
    private String mPassword = null;

    /**
     * Constructs credential object.
     *
     * @param id user id
     * @param password user password
     */
    public Credential(String id, String password) {
        mId = id;
        mPassword = password;
    }

    /**
     * Retrieves identifier.
     *
     * @return user id
     */
    public String getIdentifier() {
        return mId;
    }

    /**
     * Retrieves password.
     *
     * @return user password
     */
    public String getPassword() {
        return mPassword;
    }
}
