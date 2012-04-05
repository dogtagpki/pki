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
package com.netscape.cms.profile.constraint;

import java.util.Locale;

import netscape.security.x509.Extension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.EnrollExtDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserExtensionDefault;

/**
 * This class implements the general extension constraint.
 * It checks if the extension in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class ExtensionConstraint extends EnrollConstraint {

    public static final String CONFIG_CRITICAL = "extCritical";
    public static final String CONFIG_OID = "extOID";

    public ExtensionConstraint() {
        super();
        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_OID);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public void setConfig(String name, String value)
            throws EPropertyException {

        if (mConfig.getSubStore("params") == null) {
            CMS.debug("ExtensionConstraint: mConfig.getSubStore is null");
        } else {
            CMS.debug("ExtensionConstraint: setConfig name=" + name +
                    " value=" + value);

            if (name.equals(CONFIG_OID)) {
                try {
                    CMS.checkOID("", value);
                } catch (Exception e) {
                    throw new EPropertyException(
                            CMS.getUserMessage("CMS_PROFILE_PROPERTY_ERROR", value));
                }
            }
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_OID)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OID"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {

        Extension ext = getExtension(getConfig(CONFIG_OID), info);

        if (ext == null) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_EXTENSION_NOT_FOUND",
                            getConfig(CONFIG_OID)));
        }

        // check criticality
        String value = getConfig(CONFIG_CRITICAL);

        if (!isOptional(value)) {
            boolean critical = getBoolean(value);

            if (critical != ext.isCritical()) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_CRITICAL_NOT_MATCHED"));
            }
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_OID)
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_EXTENSION_TEXT", params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserExtensionDefault)
            return true;
        if (def instanceof EnrollExtDefault)
            return true;
        return false;
    }
}
