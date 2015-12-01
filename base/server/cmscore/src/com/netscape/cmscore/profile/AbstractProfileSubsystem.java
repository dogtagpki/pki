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
// (C) 2007  Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.profile;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedHashMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

public abstract class AbstractProfileSubsystem implements IProfileSubsystem {
    protected static final String PROP_CHECK_OWNER = "checkOwner";
    protected static final String PROP_ENABLE = "enable";
    protected static final String PROP_ENABLE_BY = "enableBy";

    protected IConfigStore mConfig = null;
    protected ISubsystem mOwner;
    protected LinkedHashMap<String, IProfile> mProfiles;
    protected Hashtable<String, String> mProfileClassIds;

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves the name of this subsystem.
     */
    public String getId() {
        return null;
    }

    /**
     * Sets specific to this subsystem.
     */
    public void setId(String id) throws EBaseException {
    }

    public boolean isProfileEnable(String id) {
        IProfile profile = mProfiles.get(id);
        String enable = null;

        try {
            enable = profile.getConfigStore().getString(PROP_ENABLE);
        } catch (EBaseException e) {
        }
        return Boolean.valueOf(enable);
    }

    public String getProfileEnableBy(String id) {
        if (!isProfileEnable(id))
            return null;
        IProfile profile = mProfiles.get(id);
        String enableBy = null;

        try {
            enableBy = profile.getConfigStore().getString(PROP_ENABLE_BY);
        } catch (EBaseException e) {
        }
        return enableBy;
    }

    /**
     * Enables a profile for execution.
     */
    public void enableProfile(String id, String enableBy)
            throws EProfileException {
        IProfile profile = mProfiles.get(id);

        profile.getConfigStore().putString(PROP_ENABLE, "true");
        profile.getConfigStore().putString(PROP_ENABLE_BY, enableBy);
    }

    /**
     * Retrieves a profile by id.
     */
    public IProfile getProfile(String id)
            throws EProfileException {
        return mProfiles.get(id);
    }

    /**
     * Disables a profile for execution.
     */
    public void disableProfile(String id)
            throws EProfileException {
        IProfile profile = mProfiles.get(id);

        profile.getConfigStore().putString(PROP_ENABLE, "false");
    }

    /**
     * Commits a profile.
     */
    public void commitProfile(String id)
            throws EProfileException {
        IConfigStore cs = mProfiles.get(id).getConfigStore();

        // first create a *new* profile object from the configStore
        // and initialise it with the updated configStore
        //
        IPluginRegistry registry = (IPluginRegistry)
            CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        String classId = mProfileClassIds.get(id);
        IPluginInfo info = registry.getPluginInfo("profile", classId);
        String className = info.getClassName();
        IProfile newProfile = null;
        try {
            newProfile = (IProfile) Class.forName(className).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new EProfileException("Could not instantiate class '"
                    + classId + "' for profile '" + id + "': " + e);
        }
        newProfile.setId(id);
        try {
            newProfile.init(this, cs);
        } catch (EBaseException e) {
            throw new EProfileException(
                    "Failed to initialise profile '" + id + "': " + e);
        }

        // next replace the existing profile with the new profile;
        // this is to avoid any intermediate state where the profile
        // is not fully initialised with its inputs, outputs and
        // policy objects.
        //
        mProfiles.put(id, newProfile);

        // finally commit the configStore
        //
        try {
            cs.commit(false);
        } catch (EBaseException e) {
            throw new EProfileException(
                "Failed to commit config store of profile '" + id + ": " + e,
                e);
        }
    }

    public String getProfileClassId(String id) {
        return mProfileClassIds.get(id);
    }

    /**
     * Retrieves a list of profile ids. The return
     * list is of type String.
     */
    public Enumeration<String> getProfileIds() {
        return Collections.enumeration(mProfiles.keySet());
    }

    /**
     * Checks if owner id should be enforced during profile approval.
     *
     * @return true if approval should be checked
     */
    public boolean checkOwner() {
        try {
            return mConfig.getBoolean(PROP_CHECK_OWNER, false);
        } catch (EBaseException e) {
            return false;
        }
    }
}
