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
package com.netscape.cms.servlet.csadmin;

import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.cms.profile.common.PolicyDefaultConfig;
import com.netscape.cms.profile.def.EnrollDefault;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

public class BootstrapProfile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BootstrapProfile.class);

    CAEngineConfig engineConfig;

    private Vector<EnrollDefault> mDefaults = new Vector<>();
    private String mName = null;
    private String mID = null;
    private String mDescription = null;
    private String mProfileIDMapping = null;
    private String mProfileSetIDMapping = null;

    public BootstrapProfile(CAEngineConfig engineConfig, ConfigStore config) throws Exception {

        this.engineConfig = engineConfig;

        mID = config.getString("id");
        mName = config.getString("name");
        mDescription = config.getString("description");
        mProfileIDMapping = config.getString("profileIDMapping");
        mProfileSetIDMapping = config.getString("profileSetIDMapping");

        StringTokenizer st = new StringTokenizer(config.getString("list"), ",");
        while (st.hasMoreTokens()) {
            String id = st.nextToken();

            PolicyDefaultConfig defaultConfig = config.getSubStore(id + ".default", PolicyDefaultConfig.class);
            String c = defaultConfig.getClassName();

            try {
                /* load defaults */
                EnrollDefault def = (EnrollDefault) Class.forName(c).getDeclaredConstructor().newInstance();
                init(defaultConfig, def);
                mDefaults.addElement(def);
            } catch (Exception e) {
                logger.warn("BootstrapProfile: Unable to create PolicyDefault: " + e.getMessage(), e);
            }
        }
    }

    private void init(PolicyDefaultConfig config, EnrollDefault def)
            throws Exception {
        try {
            def.init(engineConfig, config);
        } catch (Exception e) {
            logger.warn("BootstrapProfile: Unable to initialize PolicyDefault: " + e.getMessage(), e);
        }
    }

    public String getID() {
        return mID;
    }

    public String getName() {
        return mName;
    }

    public String getDescription() {
        return mDescription;
    }

    public String getProfileIDMapping() {
        return mProfileIDMapping;
    }

    public String getProfileSetIDMapping() {
        return mProfileSetIDMapping;
    }

    public void populate(Request request, X509CertInfo info) throws Exception {
        Enumeration<EnrollDefault> e1 = mDefaults.elements();
        while (e1.hasMoreElements()) {
            EnrollDefault def = e1.nextElement();
            try {
                logger.debug("BootstrapProfile: Populating cert with " + def.getClass().getName());
                def.populate(request, info);
            } catch (Exception e) {
                logger.error("BootstrapProfile: Unable to populate cert: " + e.getMessage(), e);
                throw e;
            }
        }
    }
}
