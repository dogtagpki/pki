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
package netscape.security.acl;

import java.security.*;

/**
 * This class implements the principal interface.
 *
 * @author 	Satish Dharmaraj
 */
public class PrincipalImpl implements Principal {

    private String user;

    /**
     * Construct a principal from a string user name.
     * @param user The string form of the principal name.
     */
    public PrincipalImpl(String user) {
	this.user = user;
    }

    /**
     * This function returns true if the object passed matches 
     * the principal represented in this implementation
     * @param another the Principal to compare with.
     * @return true if the Principal passed is the same as that 
     * encapsulated in this object, false otherwise
     */
    public boolean equals(Object another) {
	if (another instanceof PrincipalImpl) {
	    PrincipalImpl p = (PrincipalImpl) another;
	    return user.equals(p.toString());
	} else
	  return false;
    }
    
    /**
     * Prints a stringified version of the principal.
     */
    public String toString() {
	return user;
    }

    /**
     * return a hashcode for the principal.
     */
    public int hashCode() {
	return user.hashCode();
    }

    /**
     * return the name of the principal.
     */
    public String getName() {
	return user;
    }

}







