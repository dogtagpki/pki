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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.registry.PluginRegistry;

public class ProfileSubsystem
        extends AbstractProfileSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileSubsystem.class);

    public static final String ID = "profile";

    private static final String PROP_LIST = "list";
    private static final String PROP_CLASS_ID = "class_id";
    private static final String PROP_CONFIG = "config";

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     * @param cs configuration store
     *
     * @exception EBaseException failed to initialize
     */
    @Override
    public void init(IConfigStore cs)
            throws EBaseException {

        logger.debug("ProfileSubsystem: initialization");

        CAEngine engine = CAEngine.getInstance();
        PluginRegistry registry = engine.getPluginRegistry();

        mConfig = cs;

        // Configuration File Format:
        // *.list=profile1,profile2
        // *.profile1.class=com.netscape.cms.profile.common.Profile
        // *.profile1.config=config/profiles/profile1.cfg
        // *.profile2.class=com.netscape.cms.profile.common.Profile
        // *.profile2.config=config/profiles/profile2.cfg

        // read profile id, implementation, and its configuration files
        String ids = cs.getString(PROP_LIST, "");
        StringTokenizer st = new StringTokenizer(ids, ",");

        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            logger.info("ProfileSubsystem: Loading profile " + id);

            IConfigStore subStore = cs.getSubStore(id);

            String classid = subStore.getString(PROP_CLASS_ID);
            logger.debug("- class ID: " + classid);

            IPluginInfo info = registry.getPluginInfo("profile", classid);
            if (info == null) {
                throw new EBaseException("Missing plugin info: " + classid);
            }

            logger.debug("- class name: " + info.getClassName());

            String configPath = subStore.getString(PROP_CONFIG);
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
        CAEngineConfig cs = engine.getConfig();

        try {
            if (configPath == null) {
                configPath = cs.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
            }

        } catch (EBaseException e) {
            String message = "Unable to create profile: " + e.getMessage();
            logger.error(message, e);
            throw new EProfileException(message, e);
        }

        try {
            logger.debug("ProfileSubsystem: Loading " + configPath);
            IConfigStore subStoreConfig = engine.createFileConfigStore(configPath);

            logger.debug("ProfileSubsystem: Initializing " + className);
            Profile profile = (Profile) Class.forName(className).getDeclaredConstructor().newInstance();
            profile.setId(id);
            profile.init(subStoreConfig);

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

        String configPath;
        try {
            configPath = cs.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
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

        String configPath;
        try {
            configPath = cs.getInstanceDir() + "/ca/profiles/ca/" + id + ".cfg";
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
