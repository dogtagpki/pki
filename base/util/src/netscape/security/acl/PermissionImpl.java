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

import java.security.acl.Permission;

/**
 * The PermissionImpl class implements the permission
 * interface for permissions that are strings.
 *
 * @author Satish Dharmaraj
 */
public class PermissionImpl implements Permission {

    private String permission;

    /**
     * Construct a permission object using a string.
     *
     * @param permission the stringified version of the permission.
     */
    public PermissionImpl(String permission) {
        this.permission = permission;
    }

    /**
     * This function returns true if the object passed matches the permission
     * represented in this interface.
     *
     * @param another The Permission object to compare with.
     * @return true if the Permission objects are equal, false otherwise
     */
    public boolean equals(Object another) {
        if (another instanceof Permission) {
            Permission p = (Permission) another;
            return permission.equals(p.toString());
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((permission == null) ? 0 : permission.hashCode());
        return result;
    }

    /**
     * Prints a stringified version of the permission.
     *
     * @return the string representation of the Permission.
     */
    public String toString() {
        return permission;
    }
}
