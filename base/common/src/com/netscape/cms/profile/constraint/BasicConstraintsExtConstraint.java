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

import java.io.IOException;
import java.util.Locale;

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.PKIXExtensions;
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
import com.netscape.cms.profile.def.BasicConstraintsExtDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserExtensionDefault;

/**
 * This class implements the basic constraints extension constraint.
 * It checks if the basic constraint in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class BasicConstraintsExtConstraint extends EnrollConstraint {

    public static final String CONFIG_CRITICAL =
            "basicConstraintsCritical";
    public static final String CONFIG_IS_CA =
            "basicConstraintsIsCA";
    public static final String CONFIG_MIN_PATH_LEN =
            "basicConstraintsMinPathLen";
    public static final String CONFIG_MAX_PATH_LEN =
            "basicConstraintsMaxPathLen";

    public BasicConstraintsExtConstraint() {
        super();
        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_IS_CA);
        addConfigName(CONFIG_MIN_PATH_LEN);
        addConfigName(CONFIG_MAX_PATH_LEN);
    }

    /**
     * Initializes this constraint plugin.
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_IS_CA)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_IS_CA"));
        } else if (name.equals(CONFIG_MIN_PATH_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "-1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_MIN_PATH_LEN"));
        } else if (name.equals(CONFIG_MAX_PATH_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "100",
                    CMS.getUserMessage(locale, "CMS_PROFILE_MAX_PATH_LEN"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {

        try {
            BasicConstraintsExtension ext = (BasicConstraintsExtension)
                    getExtension(PKIXExtensions.BasicConstraints_Id.toString(),
                            info);

            if (ext == null) {
                throw new ERejectException(
                        CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_EXTENSION_NOT_FOUND",
                                PKIXExtensions.BasicConstraints_Id.toString()));
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
            value = getConfig(CONFIG_IS_CA);
            if (!isOptional(value)) {
                boolean isCA = getBoolean(value);
                Boolean extIsCA = (Boolean) ext.get(BasicConstraintsExtension.IS_CA);

                if (isCA != extIsCA.booleanValue()) {
                    throw new ERejectException(
                            CMS.getUserMessage(getLocale(request),
                                    "CMS_PROFILE_CONSTRAINT_BASIC_CONSTRAINTS_EXT_IS_CA"));
                }
            }
            value = getConfig(CONFIG_MIN_PATH_LEN);
            if (!isOptional(value)) {
                int pathLen = getInt(value);
                Integer extPathLen = (Integer) ext.get(BasicConstraintsExtension.PATH_LEN);

                if (pathLen > extPathLen.intValue()) {
                    CMS.debug("BasicCOnstraintsExtConstraint: pathLen=" + pathLen + " > extPathLen=" + extPathLen);
                    throw new ERejectException(
                            CMS.getUserMessage(getLocale(request),
                                    "CMS_PROFILE_CONSTRAINT_BASIC_CONSTRAINTS_EXT_MIN_PATH"));
                }
            }
            value = getConfig(CONFIG_MAX_PATH_LEN);
            if (!isOptional(value)) {
                int pathLen = getInt(value);
                Integer extPathLen = (Integer) ext.get(BasicConstraintsExtension.PATH_LEN);

                if (pathLen < extPathLen.intValue()) {
                    CMS.debug("BasicCOnstraintsExtConstraint: pathLen=" + pathLen + " < extPathLen=" + extPathLen);
                    throw new ERejectException(
                            CMS.getUserMessage(getLocale(request),
                                    "CMS_PROFILE_CONSTRAINT_BASIC_CONSTRAINTS_EXT_MAX_PATH"));
                }
            }
        } catch (IOException e) {
            CMS.debug("BasicConstraintsExt: validate " + e.toString());
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_EXTENSION_NOT_FOUND",
                            PKIXExtensions.BasicConstraints_Id.toString()));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_IS_CA),
                getConfig(CONFIG_MIN_PATH_LEN),
                getConfig(CONFIG_MAX_PATH_LEN)
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_BASIC_CONSTRAINTS_EXT_TEXT",
                params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof BasicConstraintsExtDefault)
            return true;
        if (def instanceof UserExtensionDefault)
            return true;
        return false;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {

        if (mConfig.getSubStore("params") == null) {
            CMS.debug("BasicConstraintsExt: mConfig.getSubStore is null");
            //
        } else {

            CMS.debug("BasicConstraintsExt: setConfig name " + name + " value " + value);

            if (name.equals(CONFIG_MAX_PATH_LEN)) {

                String minPathLen = getConfig(CONFIG_MIN_PATH_LEN);

                int minLen = getInt(minPathLen);

                int maxLen = getInt(value);

                if (minLen >= maxLen) {
                    CMS.debug("BasicConstraintExt:  minPathLen >= maxPathLen!");

                    throw new EPropertyException("bad value");
                }

            }
            mConfig.getSubStore("params").putString(name, value);
        }
    }
}
