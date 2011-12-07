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

import java.util.Enumeration;

import com.netscape.certsrv.base.ISubsystem;

/**
 * This represents the profile subsystem that manages a list of profiles.
 * 
 * @version $Revision$, $Date$
 */
public interface IProfileSubsystem extends ISubsystem {
    public static final String ID = "profile";

    /**
     * Retrieves a profile by id.
     * 
     * @return profile
     * @exception EProfileException failed to retrieve
     */
    public IProfile getProfile(String id) throws EProfileException;

    /**
     * Checks if a profile is approved by an agent or not.
     * 
     * @param id profile id
     * @return true if profile is approved
     */
    public boolean isProfileEnable(String id);

    /**
     * Retrieves the approver of the given profile.
     * 
     * @param id profile id
     * @return user id of the agent who has approved the profile
     */
    public String getProfileEnableBy(String id);

    /**
     * Creates new profile.
     * 
     * @param id profile id
     * @param classid implementation id
     * @param className class Name
     * @param configFile configuration file
     * @exception EProfileException failed to create profile
     */
    public IProfile createProfile(String id, String classid, String className,
            String configFile) throws EProfileException;

    /**
     * Deletes profile.
     * 
     * @param id profile id
     * @param configFile configuration file
     * @exception EProfileException failed to delete profile
     */
    public void deleteProfile(String id, String configFile)
            throws EProfileException;

    /**
     * Creates a new profile configuration file.
     * 
     * @param id profile id
     * @param classId implementation id
     * @param configPath location to create the configuration file
     * @exception failed to create profile
     */
    public void createProfileConfig(String id, String classId, String configPath)
            throws EProfileException;

    /**
     * Enables a profile.
     * 
     * @param id profile id
     * @param enableBy agent's user id
     * @exception EProfileException failed to enable profile
     */
    public void enableProfile(String id, String enableBy)
            throws EProfileException;

    /**
     * Disables a profile.
     * 
     * @param id profile id
     * @exception EProfileException failed to disable
     */
    public void disableProfile(String id) throws EProfileException;

    /**
     * Retrieves the id of the implementation of the given profile.
     * 
     * @param id profile id
     * @return implementation id managed by the registry
     */
    public String getProfileClassId(String id);

    /**
     * Retrieves a list of profile ids. The return list is of type String.
     * 
     * @return a list of profile ids
     */
    public Enumeration getProfileIds();

    /**
     * Checks if owner id should be enforced during profile approval.
     * 
     * @return true if approval should be checked
     */
    public boolean checkOwner();

}
