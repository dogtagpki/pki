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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

public class ProfileSubsystem
        extends AbstractProfileSubsystem
        implements IProfileSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileSubsystem.class);

    private static final String PROP_LIST = "list";
    private static final String PROP_CLASS_ID = "class_id";
    private static final String PROP_CONFIG = "config";

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param cs configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore cs)
            throws EBaseException {

        logger.debug("ProfileSubsystem: initialization");

        CMSEngine engine = CMS.getCMSEngine();
        IPluginRegistry registry = (IPluginRegistry) engine.getSubsystem(IPluginRegistry.ID);

        mConfig = cs;
        mOwner = owner;

        // Configuration File Format:
        // *.list=profile1,profile2
        // *.profile1.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile1.config=config/profiles/profile1.cfg
        // *.profile2.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile2.config=config/profiles/profile2.cfg

        // read profile id, implementation, and its configuration files
        String ids = cs.getString(PROP_LIST, "");
        StringTokenizer st = new StringTokenizer(ids, ",");

        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            logger.info("Creating profile: " + id);

            IConfigStore subStore = cs.getSubStore(id);
            String classid = subStore.getString(PROP_CLASS_ID);
            logger.debug("- class ID: " + classid);

            IPluginInfo info = registry.getPluginInfo("profile", classid);
            if (info == null) {
                throw new EBaseException("Missing plugin info: " + classid);
            }

            logger.debug("- class name: " + info.getClassName());
            createProfile(id, classid, info.getClassName(), false);
        }

        logger.info("Registered profiles:");
        Enumeration<String> ee = getProfileIds();

        while (ee.hasMoreElements()) {
            String id = ee.nextElement();
            logger.info("- " + id);
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

        logger.info("ProfileSubsystem: Creating " + id + " profile");

        IProfile profile = null;

        CMSEngine engine = CMS.getCMSEngine();
        IConfigStore cs = engine.getConfigStore();

        String configPath;
        try {
            configPath = engine.getConfigStore().getString("instanceRoot")
                + "/ca/profiles/ca/" + id + ".cfg";
        } catch (EBaseException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_ERROR", e);
        }

        try {
            logger.info("ProfileSubsystem: Loading " + configPath);
            IConfigStore subStoreConfig = engine.createFileConfigStore(configPath);
            profile = (IProfile) Class.forName(className).newInstance();

            logger.debug("ProfileSubsystem: initializing " + className);
            profile.setId(id);
            profile.init(this, subStoreConfig);
            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);
            if (isNew)
                createProfileConfig(id, classid);
            return profile;

        } catch (Exception e) {
            // throw exceptions
            logger.warn("Unable to create profile: " + id + ": " + e.getMessage(), e);
        }

        return null;
    }

    public void deleteProfile(String id) throws EProfileException {

        CMSEngine engine = CMS.getCMSEngine();
        String configPath;
        try {
            configPath = engine.getConfigStore().getString("instanceRoot")
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
            logger.warn("ProfileSubsystem: Unable to delete configuration: " + configPath);
        }
        mProfiles.remove(id);
        mProfileClassIds.remove(id);
        try {
            engine.getConfigStore().commit(false);
        } catch (Exception e) {
        }
    }

    private void createProfileConfig(String id, String classId)
            throws EProfileException {

        CMSEngine engine = CMS.getCMSEngine();
        String configPath;
        try {
            configPath = engine.getConfigStore().getString("instanceRoot")
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
            engine.getConfigStore().commit(true);
        } catch (EBaseException e) {
            logger.warn("Unable to create profile config: " + e.getMessage(), e);
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    public void startup() throws EBaseException {
        logger.debug("ProfileSubsystem: startup");
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
        mProfiles.clear();
        mProfileClassIds.clear();
    }
}
