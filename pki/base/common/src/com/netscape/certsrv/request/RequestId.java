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
package com.netscape.certsrv.request;

/**
 * The RequestId class represents the identifier for a particular request within
 * a request queue. This identifier may be used to retrieve the request object
 * itself from the request queue.
 * <p>
 * 
 * @version $Revision$ $Date$
 */
public final class RequestId {

    /**
     * Creates a new RequestId from its string representation.
     * <p>
     * 
     * @param id a string containing the decimal (base 10) value for the
     *            identifier.
     */
    public RequestId(String id) {
        mString = id;
    }

    /**
     * Converts the RequestId into its string representation. The string form
     * can be stored in a database (such as the LDAP directory)
     * <p>
     * 
     * @return a string containing the decimal (base 10) value for the
     *         identifier.
     */
    public String toString() {
        return mString;
    }

    /**
     * Implements Object.hashCode.
     * <p>
     * 
     * @return hash code of the object
     */
    public int hashCode() {
        return mString.hashCode();
    }

    /**
     * Implements Object.equals.
     * <p>
     * 
     * @param obj object to compare
     * @return true if objects are equal
     */
    public boolean equals(Object obj) {
        return mString.equals(obj);
    }

    // instance variables
    private final String mString;
}
