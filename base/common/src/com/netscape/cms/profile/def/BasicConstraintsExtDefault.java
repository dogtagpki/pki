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

import java.io.IOException;
import java.util.Locale;

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates Basic Constraint extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class BasicConstraintsExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "basicConstraintsCritical";
    public static final String CONFIG_IS_CA = "basicConstraintsIsCA";
    public static final String CONFIG_PATH_LEN = "basicConstraintsPathLen";

    public static final String VAL_CRITICAL = "basicConstraintsCritical";
    public static final String VAL_IS_CA = "basicConstraintsIsCA";
    public static final String VAL_PATH_LEN = "basicConstraintsPathLen";

    public BasicConstraintsExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_IS_CA);
        addValueName(VAL_PATH_LEN);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_IS_CA);
        addConfigName(CONFIG_PATH_LEN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_IS_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_IS_CA"));
        } else if (name.equals(CONFIG_PATH_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "-1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_PATH_LEN"));
        }
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_IS_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_IS_CA"));
        } else if (name.equals(VAL_PATH_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "-1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_PATH_LEN"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            BasicConstraintsExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {

                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_IS_CA)) {
                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean isCA = Boolean.valueOf(value);

                ext.set(BasicConstraintsExtension.IS_CA, isCA);
            } else if (name.equals(VAL_PATH_LEN)) {
                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

                if (ext == null) {
                    return;
                }
                Integer pathLen = Integer.valueOf(value);

                ext.set(BasicConstraintsExtension.PATH_LEN, pathLen);
            } else {
                throw new EPropertyException("Invalid name " + name);
            }
            replaceExtension(PKIXExtensions.BasicConstraints_Id.toString(),
                    ext, info);
        } catch (IOException e) {
            CMS.debug("BasicConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (EProfileException e) {
            CMS.debug("BasicConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        try {
            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            BasicConstraintsExtension ext = (BasicConstraintsExtension)
                    getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

            if (ext == null) {
                CMS.debug("BasicConstraintsExtDefault: getValue ext is null, populating a new one ");

                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    CMS.debug("BasicConstraintsExtDefault: getValue " + e.toString());
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                if (ext.isCritical()) {
                    return "true";
                } else {
                    return "false";
                }
            } else if (name.equals(VAL_IS_CA)) {
                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                Boolean isCA = (Boolean) ext.get(BasicConstraintsExtension.IS_CA);

                return isCA.toString();
            } else if (name.equals(VAL_PATH_LEN)) {
                ext = (BasicConstraintsExtension)
                        getExtension(PKIXExtensions.BasicConstraints_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                Integer pathLen = (Integer)
                        ext.get(BasicConstraintsExtension.PATH_LEN);

                String pLen = null;

                pLen = pathLen.toString();
                if (pLen.equals("-2")) {
                    //This is done for bug 621700.  Profile constraints actually checks for -1
                    //The low level security class for some reason sets this to -2
                    //This will allow the request to be approved successfuly by the agent.

                    pLen = "-1";

                }

                CMS.debug("BasicConstriantsExtDefault getValue(pLen) " + pLen);

                return pLen;

            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (IOException e) {
            CMS.debug("BasicConstraintsExtDefault: getValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_IS_CA),
                getConfig(CONFIG_PATH_LEN)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_BASIC_CONSTRAINTS_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        BasicConstraintsExtension ext = createExtension();

        addExtension(PKIXExtensions.BasicConstraints_Id.toString(), ext,
                info);
    }

    public BasicConstraintsExtension createExtension() {
        BasicConstraintsExtension ext = null;

        boolean critical = Boolean.valueOf(getConfig(CONFIG_CRITICAL)).booleanValue();
        boolean isCA = Boolean.valueOf(getConfig(CONFIG_IS_CA)).booleanValue();
        String pathLenStr = getConfig(CONFIG_PATH_LEN);

        int pathLen = -2;

        if (!pathLenStr.equals("")) {

            pathLen = Integer.valueOf(pathLenStr).intValue();
        }

        try {
            ext = new BasicConstraintsExtension(isCA, critical, pathLen);
        } catch (Exception e) {
            CMS.debug("BasicConstraintsExtDefault: createExtension " +
                    e.toString());
            return null;
        }
        ext.setCritical(critical);
        return ext;
    }
}
