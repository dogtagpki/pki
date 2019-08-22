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

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements an enrollment default policy
 * that populates server-side configurable subject name
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class nsTokenDeviceKeySubjectNameDefault extends EnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(nsTokenDeviceKeySubjectNameDefault.class);

    public static final String PROP_PARAMS = "params";
    public static final String CONFIG_DNPATTERN = "dnpattern";

    public static final String VAL_NAME = "name";

    /* default dn pattern if left blank or not set in the config */
    protected static String DEFAULT_DNPATTERN =
            "Token Key Device - $request.tokencuid$";

    protected IConfigStore mParamsConfig;

    public nsTokenDeviceKeySubjectNameDefault() {
        super();
        addConfigName(CONFIG_DNPATTERN);

        addValueName(CONFIG_DNPATTERN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        logger.debug("nsTokenDeviceKeySubjectNameDefault: in getConfigDescriptor, name=" + name);
        if (name.equals(CONFIG_DNPATTERN)) {
            return new Descriptor(IDescriptor.STRING,
                    null, null, CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_NAME"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        logger.debug("nsTokenDeviceKeySubjectNameDefault: in getValueDescriptor name=" + name);

        if (name.equals(VAL_NAME)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_NAME"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {

        logger.debug("nsTokenDeviceKeySubjectNameDefault: in setValue, value=" + value);

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            X500Name x500name = null;

            try {
                x500name = new X500Name(value);
            } catch (IOException e) {
                logger.warn("nsTokenDeviceKeySubjectNameDefault: setValue " + e.getMessage(), e);
                // failed to build x500 name
            }
            logger.debug("nsTokenDeviceKeySubjectNameDefault: setValue name=" + x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                logger.error("nsTokenDeviceKeySubjectNameDefault: setValue " + e.getMessage(), e);
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        logger.debug("nsTokenDeviceKeySubjectNameDefault: in getValue, name=" + name);
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            CertificateSubjectName sn = null;

            try {
                logger.debug("nsTokenDeviceKeySubjectNameDefault: getValue info=" + info);
                sn = (CertificateSubjectName)
                        info.get(X509CertInfo.SUBJECT);
                logger.debug("nsTokenDeviceKeySubjectNameDefault: getValue name=" + sn);
                return sn.toString();
            } catch (Exception e) {
                // nothing
                logger.warn("nsTokenDeviceKeySubjectNameDefault: getValue " + e.getMessage(), e);

            }
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        logger.debug("nsTokenDeviceKeySubjectNameDefault: in getText");
        return CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME",
                getConfig(CONFIG_DNPATTERN));
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        X500Name name = null;
        logger.debug("nsTokenDeviceKeySubjectNameDefault: in populate");

        try {
            String subjectName = getSubjectName(request);
            logger.debug("subjectName=" + subjectName);
            if (subjectName == null || subjectName.equals(""))
                return;

            name = new X500Name(subjectName);
        } catch (IOException e) {
            // failed to build x500 name
            logger.warn("nsTokenDeviceKeySubjectNameDefault: populate " + e.getMessage(), e);
        }
        if (name == null) {
            // failed to build x500 name
        }
        try {
            info.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(name));
        } catch (Exception e) {
            // failed to insert subject name
            logger.warn("nsTokenDeviceKeySubjectNameDefault: populate " + e.getMessage(), e);
        }
    }

    private String getSubjectName(IRequest request)
            throws EProfileException, IOException {

        logger.debug("nsTokenDeviceKeySubjectNameDefault: in getSubjectName");

        String pattern = getConfig(CONFIG_DNPATTERN);
        if (pattern == null || pattern.equals("")) {
            pattern = " ";
        }

        String sbjname = "";

        if (request != null) {
            logger.debug("pattern = " + pattern);
            sbjname = mapPattern(request, pattern);
            logger.debug("nsTokenDeviceKeySubjectNameDefault: getSubjectName(): subject name mapping done");
        }

        return sbjname;
    }
}
