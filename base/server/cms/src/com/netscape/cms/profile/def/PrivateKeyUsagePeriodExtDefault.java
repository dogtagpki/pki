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

import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.PrivateKeyUsageExtension;
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
 * that populates a Private Key Usage Period extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class PrivateKeyUsagePeriodExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "puCritical";
    public static final String CONFIG_START_TIME = "puStartTime";
    public static final String CONFIG_DURATION = "puDurationInDays"; // in days

    public static final String VAL_CRITICAL = "puCritical";
    public static final String VAL_NOT_BEFORE = "puNotBefore";
    public static final String VAL_NOT_AFTER = "puNotAfter";

    public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private long mDefault = 86400000; // 1 days

    public PrivateKeyUsagePeriodExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_NOT_BEFORE);
        addValueName(VAL_NOT_AFTER);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_START_TIME);
        addConfigName(CONFIG_DURATION);
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
        } else if (name.equals(CONFIG_START_TIME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "0",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_START_TIME"));
        } else if (name.equals(CONFIG_DURATION)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "365",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_RANGE"));
        } else {
            return null;
        }
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_START_TIME)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_START_TIME));
            }
        } else if (name.equals(CONFIG_DURATION)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_DURATION));
            }
        }
        super.setConfig(name, value);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_NOT_BEFORE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "0",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_BEFORE"));
        } else if (name.equals(VAL_NOT_AFTER)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "30",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_AFTER"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            PrivateKeyUsageExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ObjectIdentifier oid = PKIXExtensions.PrivateKeyUsage_Id;

            ext = (PrivateKeyUsageExtension)
                        getExtension(oid.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {

                ext = (PrivateKeyUsageExtension)
                        getExtension(oid.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_NOT_BEFORE)) {
                SimpleDateFormat formatter =
                        new SimpleDateFormat(DATE_FORMAT);
                ParsePosition pos = new ParsePosition(0);
                Date date = formatter.parse(value, pos);

                ext = (PrivateKeyUsageExtension)
                        getExtension(oid.toString(), info);

                if (ext == null) {
                    return;
                }
                ext.set(PrivateKeyUsageExtension.NOT_BEFORE, date);
            } else if (name.equals(VAL_NOT_AFTER)) {
                SimpleDateFormat formatter =
                        new SimpleDateFormat(DATE_FORMAT);
                ParsePosition pos = new ParsePosition(0);
                Date date = formatter.parse(value, pos);

                ext = (PrivateKeyUsageExtension)
                        getExtension(oid.toString(), info);

                if (ext == null) {
                    return;
                }
                ext.set(PrivateKeyUsageExtension.NOT_AFTER, date);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(ext.getExtensionId().toString(), ext, info);
        } catch (EProfileException e) {
            CMS.debug("PrivateKeyUsageExtension: setValue " + e.toString());
        } catch (Exception e) {
            CMS.debug("PrivateKeyUsageExtension: setValue " + e.toString());
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        PrivateKeyUsageExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ObjectIdentifier oid = PKIXExtensions.PrivateKeyUsage_Id;

        ext = (PrivateKeyUsageExtension)
                    getExtension(oid.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {

            ext = (PrivateKeyUsageExtension)
                    getExtension(oid.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_NOT_BEFORE)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);

            ext = (PrivateKeyUsageExtension)
                    getExtension(oid.toString(), info);

            if (ext == null)
                return "";

            return formatter.format(ext.getNotBefore());
        } else if (name.equals(VAL_NOT_AFTER)) {
            SimpleDateFormat formatter =
                    new SimpleDateFormat(DATE_FORMAT);

            ext = (PrivateKeyUsageExtension)
                    getExtension(oid.toString(), info);

            if (ext == null)
                return "";

            return formatter.format(ext.getNotAfter());
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_START_TIME),
                getConfig(CONFIG_DURATION)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_PRIVATE_KEY_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        PrivateKeyUsageExtension ext = createExtension();

        addExtension(ext.getExtensionId().toString(), ext, info);
    }

    public PrivateKeyUsageExtension createExtension() {
        PrivateKeyUsageExtension ext = null;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);

            // always + 60 seconds
            String startTimeStr = getConfig(CONFIG_START_TIME);

            if (startTimeStr == null || startTimeStr.equals("")) {
                startTimeStr = "60";
            }
            int startTime = Integer.parseInt(startTimeStr);
            Date notBefore = new Date(CMS.getCurrentDate().getTime() +
                    (1000 * startTime));
            long notAfterVal = 0;

            notAfterVal = notBefore.getTime() +
                    (mDefault * Integer.parseInt(getConfig(CONFIG_DURATION)));
            Date notAfter = new Date(notAfterVal);

            ext = new PrivateKeyUsageExtension(notBefore, notAfter);
            ext.setCritical(critical);
        } catch (Exception e) {
            CMS.debug("PrivateKeyUsagePeriodExt: createExtension " +
                    e.toString());
        }
        return ext;
    }
}
