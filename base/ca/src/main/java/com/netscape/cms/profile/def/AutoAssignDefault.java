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
package com.netscape.cms.profile.def;

import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements an enrollment default policy
 * that automatically assign request to agent.
 *
 * @version $Revision$, $Date$
 */
public class AutoAssignDefault extends EnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AutoAssignDefault.class);
    public static final String CONFIG_ASSIGN_TO = "assignTo";

    public AutoAssignDefault() {
        super();
        addConfigName(CONFIG_ASSIGN_TO);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_ASSIGN_TO)) {
            return new Descriptor(IDescriptor.STRING,
                    null, "admin", CMS.getUserMessage(locale,
                            "CMS_PROFILE_AUTO_ASSIGN"));
        } else {
            return null;
        }
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
    }

    @Override
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        return null;
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_AUTO_ASSIGN",
                getConfig(CONFIG_ASSIGN_TO));
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        try {
            request.setRequestOwner(
                    mapPattern(request, getConfig(CONFIG_ASSIGN_TO)));
        } catch (Exception e) {
            // failed to insert subject name
            logger.warn("AutoAssignDefault: populate " + e.getMessage(), e);
        }
    }
}
