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
package com.netscape.certsrv.acls;


import java.util.Enumeration;


/**
 * A class represents an access control list (ACL). An ACL
 * is associated with a protected resource. The policy 
 * enforcer can verify the ACLs with the current
 * context to see if the corresponding resource is accessible.  
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IACL { 

    /**
     * Returns the name of the current ACL.
     * @return the name of the current ACL.
     */
    public String getName();

    /**
     * Returns the description of the current ACL.
     * @return the description of the current ACL.
     */
    public String getDescription(); 

    /**
     * Returns a list of access rights of the current ACL.
     * @return a list of access rights
     */
    public Enumeration rights(); 

    /**
     * Returns a list of entries of the current ACL.
     * @return a list of entries
     */
    public Enumeration entries();

    /**
     * Verifies if permission is granted.
     * @param permission one of the applicable rights
     * @return true if the given permission is one of the applicable rights; false otherwise.
     */
    public boolean checkRight(String permission);
}
