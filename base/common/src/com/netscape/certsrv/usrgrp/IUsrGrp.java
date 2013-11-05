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

import java.io.Serializable;

/**
 * This interface defines the basic capabilities of
 * a usr/group manager. (get/add/modify/remove users or groups)
 *
 * @version $Revision$, $Date$
 */
public interface IUsrGrp extends IIdEvaluator , Serializable {

    /**
     * Retrieves usr/grp manager identifier.
     *
     * @return id
     */
    public String getId();

    /**
     * Retrieves the description
     *
     * @return description
     */
    public String getDescription();

    /**
     * Retrieves an identity
     *
     * @param userid the user id for the given user
     * @return user interface
     */
    public IUser getUser(String userid) throws EUsrGrpException;

    /**
     * Adds a user identity to the LDAP server. For example, <code>
     *   User user = new User("joe");
     *   user.setFullName("joe doe");
     *   user.setPassword("secret");
     *   usrgrp.addUser(user);
     * </code>
     *
     * @param user an user interface
     * @exception EUsrGrpException thrown when some of the user attribute values
     *                are null
     */
    public void addUser(IUser user) throws EUsrGrpException;

    /**
     * Removes a user.
     *
     * @param userid the user id for the given user
     * @exception EUsrGrpException thrown when failed to remove user
     */
    public void removeUser(String userid) throws EUsrGrpException;

    /**
     * Modifies user.
     *
     * @param user the user interface which contains the modified information
     * @exception EUsrGrpException thrown when failed to modify user
     */
    public void modifyUser(IUser user) throws EUsrGrpException;

    /**
     * Retrieves an identity group
     *
     * @param groupid the given group id.
     * @return the group interface
     */
    public IGroup getGroup(String groupid);

    /**
     * Adds a group
     *
     * @param group the given group
     * @exception EUsrGrpException thrown when failed to add the group.
     */
    public void addGroup(IGroup group) throws EUsrGrpException;

    /**
     * Modifies a group
     *
     * @param group the given group contains the new information for modification.
     * @exception EUsrGrpException thrown when failed to modify the group.
     */
    public void modifyGroup(IGroup group) throws EUsrGrpException;

    /**
     * Removes a group
     *
     * @param name the group name
     * @exception EUsrGrpException thrown when failed to remove the given
     *                group.
     */
    public void removeGroup(String name) throws EUsrGrpException;

}
