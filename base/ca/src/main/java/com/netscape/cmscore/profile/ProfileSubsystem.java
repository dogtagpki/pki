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
import java.util.StringTokenizer;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.registry.PluginInfo;
import com.netscape.cmscore.registry.PluginRegistry;

public class ProfileSubsystem
        extends AbstractProfileSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileSubsystem.class);

    public static final String ID = "profile";

    private static final String PROP_LIST = "list";
    private static final String PROP_CLASS_ID = "class_id";

    /**
     * Initializes this subsystem with the given configuration
     * store.
     *
     * @param config Subsystem configuration
     * @exception Exception Unable to initialize subsystem
     */
    @Override
    public void init(ConfigStore config) throws Exception {

        logger.debug("ProfileSubsystem: initialization");

        CAEngine engine = CAEngine.getInstance();
        PluginRegistry registry = engine.getPluginRegistry();

        mConfig = config;

        // Configuration File Format:
        // *.list=profile1,profile2
        // *.profile1.class=com.netscape.cms.profile.common.Profile
        // *.profile2.class=com.netscape.cms.profile.common.Profile

        // read profile id, implementation, and its configuration files
        String ids = config.getString(PROP_LIST, "");
        StringTokenizer st = new StringTokenizer(ids, ",");

        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            logger.info("ProfileSubsystem: Loading profile " + id);

            ConfigStore subStore = config.getSubStore(id, ConfigStore.class);

            String classid = subStore.getString(PROP_CLASS_ID);
            logger.debug("- class ID: " + classid);

            PluginInfo info = registry.getPluginInfo("profile", classid);
            if (info == null) {
                throw new EBaseException("Missing plugin info: " + classid);
            }

            logger.debug("- class name: " + info.getClassName());

            String configPath = CMS.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
            logger.debug("- config: " + configPath);

            createProfile(id, classid, info.getClassName(), configPath, false);
        }

        logger.debug("Registered profiles:");
        Enumeration<String> ee = getProfileIds();

        while (ee.hasMoreElements()) {
            String id = ee.nextElement();
            logger.debug("- " + id);
        }
    }

    /**
     * Creates a profile instance.
     */
    public Profile createProfile(String id, String classid, String className)
            throws EProfileException {
        return createProfile(id, classid, className, null, true);
    }

    private Profile createProfile(String id, String classid, String className,
            String configPath,
            boolean isNew) throws EProfileException {

        logger.debug("ProfileSubsystem: Creating " + id + " profile");

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();
        PluginRegistry registry = engine.getPluginRegistry();

        if (configPath == null) {
            configPath = CMS.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
        }
        logger.debug("- config: " + configPath);

        try {
            // if the file is not there, create one
            File file = new File(configPath);
            file.createNewFile();

            ConfigStorage storage = new FileConfigStorage(configPath);
            ProfileConfig profileConfig = new ProfileConfig(storage);
            profileConfig.load();

            logger.debug("ProfileSubsystem: Initializing " + className);
            Profile profile = (Profile) Class.forName(className).getDeclaredConstructor().newInstance();
            profile.setId(id);
            profile.init(engineConfig, registry, profileConfig);

            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);

            if (isNew) {
                createProfileConfig(id, classid);
            }

            return profile;

        } catch (Exception e) {
            // throw exceptions
            logger.warn("Unable to create profile: " + e.getMessage(), e);
        }

        return null;
    }

    public void deleteProfile(String id) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        String configPath = CMS.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
        logger.debug("- config: " + configPath);

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
            logger.warn("ProfileSubsystem: Unable to delete configuration: " + configPath);
        }
        mProfiles.remove(id);
        mProfileClassIds.remove(id);
        try {
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    private void createProfileConfig(String id, String classId)
            throws EProfileException {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        try {
            if (mProfiles.size() > 0) {
                mConfig.putString(PROP_LIST,
                        mConfig.getString(PROP_LIST) + "," + id);
            } else {
                mConfig.putString(PROP_LIST, id);
            }

            mConfig.putString(id + "." + PROP_CLASS_ID, classId);
            cs.commit(true);

        } catch (EBaseException e) {
            logger.warn("Unable to create profile config: " + e.getMessage(), e);
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    @Override
    public void startup() throws EBaseException {
        logger.debug("ProfileSubsystem: startup");
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    @Override
    public void shutdown() {
        mProfiles.clear();
        mProfileClassIds.clear();
    }
}
