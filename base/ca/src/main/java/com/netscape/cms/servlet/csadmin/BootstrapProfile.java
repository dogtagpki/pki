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

import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.EnrollDefault;

public class BootstrapProfile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BootstrapProfile.class);

    private Vector<EnrollDefault> mDefaults = new Vector<>();
    private String mName = null;
    private String mID = null;
    private String mDescription = null;
    private String mProfileIDMapping = null;
    private String mProfileSetIDMapping = null;

    public BootstrapProfile(IConfigStore config) throws Exception {
        mID = config.getString("id");
        mName = config.getString("name");
        mDescription = config.getString("description");
        mProfileIDMapping = config.getString("profileIDMapping");
        mProfileSetIDMapping = config.getString("profileSetIDMapping");
        StringTokenizer st = new StringTokenizer(config.getString("list"), ",");
        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            String c = config.getString(id + ".default.class");
            try {
                /* load defaults */
                EnrollDefault def = (EnrollDefault) Class.forName(c).getDeclaredConstructor().newInstance();
                init(config.getSubStore(id + ".default"), def);
                mDefaults.addElement(def);
            } catch (Exception e) {
                logger.warn("BootstrapProfile: Unable to create PolicyDefault: " + e.getMessage(), e);
            }
        }
    }

    private void init(IConfigStore config, EnrollDefault def)
            throws Exception {
        try {
            def.init(config);
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

    public void populate(IRequest request, X509CertInfo info) throws Exception {
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
