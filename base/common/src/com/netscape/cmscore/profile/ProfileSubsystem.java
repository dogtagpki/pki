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
package com.netscape.cmscore.profile;

import java.io.File;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

public class ProfileSubsystem implements IProfileSubsystem {
    private static final String PROP_LIST = "list";
    private static final String PROP_CLASS_ID = "class_id";
    private static final String PROP_CONFIG = "config";
    private static final String PROP_CHECK_OWNER = "checkOwner";

    private static final String PROP_ENABLE = "enable";
    private static final String PROP_ENABLE_BY = "enableBy";

    private IConfigStore mConfig = null;
    @SuppressWarnings("unused")
    private ISubsystem mOwner;
    private Vector<String> mProfileIds = new Vector<String>();
    private Hashtable<String, IProfile> mProfiles = new Hashtable<String, IProfile>();
    private Hashtable<String, String> mProfileClassIds = new Hashtable<String, String>();

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

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        CMS.debug("ProfileSubsystem: start init");
        IPluginRegistry registry = (IPluginRegistry)
                CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);

        mConfig = config;
        mOwner = owner;

        // Configuration File Format:
        // *.list=profile1,profile2
        // *.profile1.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile1.config=config/profiles/profile1.cfg
        // *.profile2.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile2.config=config/profiles/profile2.cfg

        // read profile id, implementation, and its configuration files
        String ids = config.getString(PROP_LIST, "");
        StringTokenizer st = new StringTokenizer(ids, ",");

        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            IConfigStore subStore = config.getSubStore(id);
            String classid = subStore.getString(PROP_CLASS_ID);
            IPluginInfo info = registry.getPluginInfo("profile", classid);
            if (info == null) {
                throw new EBaseException("No plugins for type : profile, with id " + classid);
            }
            String configPath = subStore.getString(PROP_CONFIG);

            CMS.debug("Start Profile Creation - " + id + " " + classid + " " + info.getClassName());
            createProfile(id, classid, info.getClassName(),
                    configPath);

            CMS.debug("Done Profile Creation - " + id);
        }

        Enumeration<String> ee = getProfileIds();

        while (ee.hasMoreElements()) {
            String id = ee.nextElement();

            CMS.debug("Registered Confirmation - " + id);
        }
    }

    /**
     * Creates a profile instance.
     */
    public IProfile createProfile(String id, String classid, String className,
            String configPath)
            throws EProfileException {
        IProfile profile = null;

        try {
            profile = (IProfile) Class.forName(className).newInstance();
            IConfigStore subStoreConfig = CMS.createFileConfigStore(configPath);

            CMS.debug("ProfileSubsystem: initing " + className);
            profile.setId(id);
            profile.init(this, subStoreConfig);
            mProfileIds.addElement(id);
            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);
            return profile;
        } catch (Exception e) {
            // throw exceptions
            CMS.debug(e.toString());
            CMS.debug(e);
        }
        return null;
    }

    public void deleteProfile(String id, String configPath) throws EProfileException {

        if (isProfileEnable(id)) {
            throw new EProfileException("CMS_PROFILE_DELETE_ENABLEPROFILE");
        }

        String ids = "";
        try {
            ids = mConfig.getString(PROP_LIST, "");
        } catch (Exception e) {
        }

        StringTokenizer tokenizer = new StringTokenizer(ids, ",");
        StringBuffer list = new StringBuffer();

        while (tokenizer.hasMoreTokens()) {
            String element = tokenizer.nextToken();

            if (!element.equals(id)) {
                list.append(element + ",");
            }
        }
        if (list.length() != 0)
            list.deleteCharAt(list.length() - 1);

        mConfig.putString(PROP_LIST, list.toString());
        mConfig.removeSubStore(id);
        File file1 = new File(configPath);

        if (!file1.delete()) {
            CMS.debug("ProfileSubsystem: deleteProfile: Cannot delete the configuration file : " + configPath);
        }
        mProfileIds.removeElement(id);
        mProfiles.remove(id);
        mProfileClassIds.remove(id);
        try {
            CMS.getConfigStore().commit(false);
        } catch (Exception e) {
        }
    }

    public void createProfileConfig(String id, String classId,
            String configPath)
            throws EProfileException {
        try {
            if (mProfiles.size() > 0) {
                mConfig.putString(PROP_LIST,
                        mConfig.getString(PROP_LIST) + "," + id);
            } else {
                mConfig.putString(PROP_LIST, id);
            }
            mConfig.putString(id + "." + PROP_CLASS_ID, classId);
            mConfig.putString(id + "." + PROP_CONFIG, configPath);
            CMS.getConfigStore().commit(true);
        } catch (EBaseException e) {
            CMS.debug(e.toString());
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    public void startup() throws EBaseException {
        CMS.debug("ProfileSubsystem: startup");
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
        mProfileIds.clear();
        mProfiles.clear();
        mProfileClassIds.clear();
    }

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
     * Adds a profile.
     */
    public void addProfile(String id, IProfile profile)
            throws EProfileException {
    }

    public boolean isProfileEnable(String id) {
        IProfile profile = mProfiles.get(id);
        String enable = null;

        try {
            enable = profile.getConfigStore().getString(PROP_ENABLE);
        } catch (EBaseException e) {
        }
        if (enable == null || enable.equals("false"))
            return false;
        else
            return true;
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
        try {
            profile.getConfigStore().commit(false);
        } catch (EBaseException e) {
        }
    }

    /**
     * Disables a profile for execution.
     */
    public void disableProfile(String id)
            throws EProfileException {
        IProfile profile = mProfiles.get(id);

        profile.getConfigStore().putString(PROP_ENABLE, "false");
        try {
            profile.getConfigStore().commit(false);
        } catch (EBaseException e) {
        }
    }

    /**
     * Retrieves a profile by id.
     */
    public IProfile getProfile(String id)
            throws EProfileException {
        return mProfiles.get(id);
    }

    public String getProfileClassId(String id) {
        return mProfileClassIds.get(id);
    }

    /**
     * Retrieves a list of profile ids. The return
     * list is of type String.
     */
    public Enumeration<String> getProfileIds() {
        return mProfileIds.elements();
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
