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

public class ProfileSubsystem
        extends AbstractProfileSubsystem
        implements IProfileSubsystem {
    private static final String PROP_LIST = "list";
    private static final String PROP_CLASS_ID = "class_id";
    private static final String PROP_CONFIG = "config";

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

        mProfileIds = new Vector<String>();
        mProfiles = new Hashtable<String, IProfile>();
        mProfileClassIds = new Hashtable<String, String>();

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
            createProfile(id, classid, info.getClassName(), false);

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
    @Override
    public IProfile createProfile(String id, String classid, String className)
            throws EProfileException {
        return createProfile(id, classid, className, true);
    }

    private IProfile createProfile(String id, String classid, String className,
            boolean isNew) throws EProfileException {
        IProfile profile = null;

        String configPath;
        try {
            configPath = CMS.getConfigStore().getString("instanceRoot")
                + "/ca/profiles/ca/" + id + ".cfg";
        } catch (EBaseException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_ERROR");
        }

        try {
            IConfigStore subStoreConfig = CMS.createFileConfigStore(configPath);
            profile = (IProfile) Class.forName(className).newInstance();

            CMS.debug("ProfileSubsystem: initing " + className);
            profile.setId(id);
            profile.init(this, subStoreConfig);
            mProfileIds.addElement(id);
            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);
            if (isNew)
                createProfileConfig(id, classid);
            return profile;
        } catch (Exception e) {
            // throw exceptions
            CMS.debug(e.toString());
            CMS.debug(e);
        }
        return null;
    }

    public void deleteProfile(String id) throws EProfileException {
        String configPath;
        try {
            configPath = CMS.getConfigStore().getString("instanceRoot")
                + "/ca/profiles/ca/" + id + ".cfg";
        } catch (EBaseException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_ERROR");
        }

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

    private void createProfileConfig(String id, String classId)
            throws EProfileException {
        String configPath;
        try {
            configPath = CMS.getConfigStore().getString("instanceRoot")
                + "/ca/profiles/ca/" + id + ".cfg";
        } catch (EBaseException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_ERROR");
        }

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
}
