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
package com.netscape.certsrv.profile;

/**
 * This interface represents a profile policy
 * which consists a default policy and a
 * constraint policy.
 * 
 * @version $Revision$, $Date$
 */
public interface IProfilePolicy {

    /**
     * Retrieves the policy id
     * 
     * @return policy id
     */
    public String getId();

    /**
     * Retrieves the default policy.
     * 
     * @return default policy
     */
    public IPolicyDefault getDefault();

    /**
     * Retrieves the constraint policy.
     * 
     * @return constraint policy
     */
    public IPolicyConstraint getConstraint();
}
