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
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import netscape.security.x509.CertificateValidity;
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
 * that populates a server-side configurable validity
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class ValidityDefault extends EnrollDefault {
    public static final String CONFIG_RANGE = "range";
    public static final String CONFIG_START_TIME = "startTime";

    public static final String VAL_NOT_BEFORE = "notBefore";
    public static final String VAL_NOT_AFTER = "notAfter";

    public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    private long mDefault = 86400000; // 1 days

    public ValidityDefault() {
        super();
        addConfigName(CONFIG_RANGE);
        addConfigName(CONFIG_START_TIME);
        addValueName(VAL_NOT_BEFORE);
        addValueName(VAL_NOT_AFTER);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_RANGE)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_RANGE));
            }
        } else if (name.equals(CONFIG_START_TIME)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_START_TIME));
            }
        }
        super.setConfig(name, value);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_RANGE)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "7305",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_VALIDITY_RANGE"));
        } else if (name.equals(CONFIG_START_TIME)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "60", /* 1 minute */
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_VALIDITY_START_TIME"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_NOT_BEFORE)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_BEFORE"));
        } else if (name.equals(VAL_NOT_AFTER)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_AFTER"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (value == null || value.equals("")) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NOT_BEFORE)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);
            ParsePosition pos = new ParsePosition(0);
            Date date = formatter.parse(value, pos);
            CertificateValidity validity = null;

            try {
                validity = (CertificateValidity)
                        info.get(X509CertInfo.VALIDITY);
                validity.set(CertificateValidity.NOT_BEFORE,
                        date);
            } catch (Exception e) {
                CMS.debug("ValidityDefault: setValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else if (name.equals(VAL_NOT_AFTER)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);
            ParsePosition pos = new ParsePosition(0);
            Date date = formatter.parse(value, pos);
            CertificateValidity validity = null;

            try {
                validity = (CertificateValidity)
                        info.get(X509CertInfo.VALIDITY);
                validity.set(CertificateValidity.NOT_AFTER,
                        date);
            } catch (Exception e) {
                CMS.debug("ValidityDefault: setValue " + e.toString());
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

        if (name == null)
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));

        if (name.equals(VAL_NOT_BEFORE)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);
            CertificateValidity validity = null;

            try {
                validity = (CertificateValidity)
                        info.get(X509CertInfo.VALIDITY);
                return formatter.format((Date)
                        validity.get(CertificateValidity.NOT_BEFORE));
            } catch (Exception e) {
                CMS.debug("ValidityDefault: getValue " + e.toString());
            }
            throw new EPropertyException("Invalid valie");
        } else if (name.equals(VAL_NOT_AFTER)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);
            CertificateValidity validity = null;

            try {
                validity = (CertificateValidity)
                        info.get(X509CertInfo.VALIDITY);
                return formatter.format((Date)
                        validity.get(CertificateValidity.NOT_AFTER));
            } catch (Exception e) {
                CMS.debug("ValidityDefault: getValue " + e.toString());
            }
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_VALIDITY",
                getConfig(CONFIG_RANGE));
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        // always + 60 seconds
        String startTimeStr = getConfig(CONFIG_START_TIME);
        try {
            startTimeStr = mapPattern(request, startTimeStr);
        } catch (IOException e) {
            CMS.debug("ValidityDefault: populate " + e.toString());
        }

        if (startTimeStr == null || startTimeStr.equals("")) {
            startTimeStr = "60";
        }
        int startTime = Integer.parseInt(startTimeStr);
        Date notBefore = new Date(CMS.getCurrentDate().getTime() + (1000 * startTime));
        long notAfterVal = 0;

        try {
            String rangeStr = getConfig(CONFIG_RANGE);
            rangeStr = mapPattern(request, rangeStr);
            notAfterVal = notBefore.getTime() +
                    (mDefault * Integer.parseInt(rangeStr));
        } catch (Exception e) {
            // configured value is not correct
            CMS.debug("ValidityDefault: populate " + e.toString());
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_INVALID_PROPERTY", CONFIG_RANGE));
        }
        Date notAfter = new Date(notAfterVal);
        CertificateValidity validity =
                new CertificateValidity(notBefore, notAfter);

        try {
            info.set(X509CertInfo.VALIDITY, validity);
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("ValidityDefault: populate " + e.toString());
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_INVALID_PROPERTY", X509CertInfo.VALIDITY));
        }
    }
}
