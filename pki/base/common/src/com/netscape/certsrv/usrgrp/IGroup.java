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


import java.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;


/**
 * This interface defines the basic interfaces for
 * an identity group. (get/set methods for a group entry attributes)
 *
 * @version $Revision$, $Date$
 */
public interface IGroup extends IAttrSet, IGroupConstants {

    /**
     * Retrieves the group name.
     * @return the group name
     */
    public String getName();

    /**
     * Retrieves group identifier.
     * @return the group id
     */
    public String getGroupID();

    /**
     * Retrieves group description.
     * @return description
     */
    public String getDescription();

    /**
     * Checks if the given name is member of this group.
     * @param name the given name
     * @return true if the given name is the member of this group; otherwise false.
     */
    public boolean isMember(String name);

    /**
     * Adds new member.
     * @param name the given name.
     */
    public void addMemberName(String name);

    /**
     * Retrieves a list of member names.
     * @return a list of member names for this group.
     */
    public Enumeration getMemberNames();
}
