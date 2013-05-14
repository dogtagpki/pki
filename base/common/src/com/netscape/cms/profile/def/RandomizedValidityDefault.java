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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

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
public class RandomizedValidityDefault extends EnrollDefault {
    public static final String CONFIG_RANGE = "range";
    public static final String CONFIG_START_TIME = "startTime";
    public static final String CONFIG_NOT_BEFORE_RANDOM_BITS = "notBeforeRandomBits";
    public static final String CONFIG_NOT_AFTER_RANDOM_BITS = "startTimeRandomBits";

    public static final String VAL_NOT_BEFORE = "notBefore";
    public static final String VAL_NOT_AFTER = "notAfter";

    public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    private long mDayInMS = 86400000; // 1 days
    private Random mRandom = null;

    public RandomizedValidityDefault() {
        super();
        addConfigName(CONFIG_RANGE);
        addConfigName(CONFIG_START_TIME);
        addConfigName(CONFIG_NOT_BEFORE_RANDOM_BITS);
        addConfigName(CONFIG_NOT_AFTER_RANDOM_BITS);
        addValueName(VAL_NOT_BEFORE);
        addValueName(VAL_NOT_AFTER);
        mRandom = new Random();
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
        } else if (name.equals(CONFIG_NOT_BEFORE_RANDOM_BITS)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NOT_BEFORE_RANDOM_BITS));
            }
        } else if (name.equals(CONFIG_NOT_AFTER_RANDOM_BITS)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NOT_AFTER_RANDOM_BITS));
            }
        }
        super.setConfig(name, value);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_RANGE)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "365", /* 365 days */
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_VALIDITY_RANGE"));
        } else if (name.equals(CONFIG_START_TIME)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "0", /* 0 seconds */
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_VALIDITY_START_TIME"));
        } else if (name.equals(CONFIG_NOT_BEFORE_RANDOM_BITS)) {
            return new Descriptor(IDescriptor.STRING,
                    null, 
                    "10", /* 10 bits */
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_NOT_BEFORE_RANDOM_BITS"));
        } else if (name.equals(CONFIG_NOT_AFTER_RANDOM_BITS)) {
            return new Descriptor(IDescriptor.STRING,
                    null, 
                    "10", /* 10 bits */
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_NOT_AFTER_RANDOM_BITS"));
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
                CMS.debug("RandomizedValidityDefault: setValue " + e.toString());
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
                CMS.debug("RandomizedValidityDefault: setValue " + e.toString());
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
                CMS.debug("RandomizedValidityDefault: getValue " + e.toString());
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
                CMS.debug("RandomizedValidityDefault: getValue " + e.toString());
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

    private int randomSecs(int numBits) {
        int maxSecs = 0;
        int secs = 0;

        if (numBits > Integer.SIZE) {
            numBits = Integer.SIZE;
            CMS.debug("RandomizedValidityDefault randomSecs "+
                      "- number of bits limited to "+numBits);
        }
        if (numBits > 0) {
            maxSecs = (1 << numBits) - 1;
            int numBytes = (numBits+7)/8;
            int byteSecs = (1 << (numBytes * 8)) - 1;
            byte[] randomBits = new byte[numBytes];
            mRandom.nextBytes(randomBits);
            for (int i = 0; i < numBytes; i++) {
                secs <<= 8;
                secs |= (int)(randomBits[i]) & 0xFF;
            }
            secs &= maxSecs;
        }
        CMS.debug("RandomizedValidityDefault randomSecs  numBits="+numBits+
                  "  secs="+secs+"  maxSecs="+maxSecs);
        return secs;
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
            CMS.debug("RandomizedValidityDefault: populate " + e.toString());
        }

        if (startTimeStr == null || startTimeStr.equals("")) {
            startTimeStr = "60";
        }
        int startTime = Integer.parseInt(startTimeStr);

        String notBeforeRandomBitsStr = getConfig(CONFIG_NOT_BEFORE_RANDOM_BITS);
        if (notBeforeRandomBitsStr == null || notBeforeRandomBitsStr.length() == 0) {
            notBeforeRandomBitsStr = "0";
        }
        int notBeforeRandomBits = Integer.parseInt(notBeforeRandomBitsStr);

        String notAfterRandomBitsStr = getConfig(CONFIG_NOT_AFTER_RANDOM_BITS);
        if (notAfterRandomBitsStr == null || notAfterRandomBitsStr.length() == 0) {
            notAfterRandomBitsStr = "0";
        }
        int notAfterRandomBits = Integer.parseInt(notAfterRandomBitsStr);
        int randomSeconds = randomSecs(notBeforeRandomBits);
        long currentTime = CMS.getCurrentDate().getTime();
        Date notBefore = new Date(currentTime + (1000 * startTime));
        CMS.debug("RandomizedValidityDefault populate  notBefore           = "+notBefore);
        Date notBeforeRandomized = new Date(currentTime + (1000 * (startTime - randomSeconds)));
        CMS.debug("RandomizedValidityDefault populate  notBeforeRandomized = "+notBeforeRandomized);
        int maxNotBeforeSecs = (1 << notBeforeRandomBits) - 1;
        Date notBeforeMax = new Date(currentTime + (1000 * (startTime - maxNotBeforeSecs)));
        CMS.debug("RandomizedValidityDefault populate  notBeforeMax        = "+notBeforeMax);

        long notAfterValue = 0;
        long notAfterValueRandomized = 0;
        long notAfterValueMax = 0;

        try {
            String rangeStr = getConfig(CONFIG_RANGE);
            rangeStr = mapPattern(request, rangeStr);
            notAfterValue = notBefore.getTime() + (mDayInMS * Integer.parseInt(rangeStr));
            notAfterValueRandomized = notBefore.getTime() + (mDayInMS * Integer.parseInt(rangeStr)) +
                                      (1000 * randomSecs(notAfterRandomBits));
            int maxNotAfterSecs = (1 << notAfterRandomBits) - 1;
            notAfterValueMax = notBefore.getTime() + (mDayInMS * Integer.parseInt(rangeStr)) +
                               (1000 * maxNotAfterSecs);
        } catch (Exception e) {
            // configured value is not correct
            CMS.debug("RandomizedValidityDefault: populate " + e.toString());
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_INVALID_PROPERTY", CONFIG_RANGE));
        }
        Date notAfter = new Date(notAfterValue);
        CMS.debug("RandomizedValidityDefault populate  notAfter            = "+notAfter);
        Date notAfterRandomized = new Date(notAfterValueRandomized);
        CMS.debug("RandomizedValidityDefault populate  notAfterRandomized  = "+notAfterRandomized);
        Date notAfterMax = new Date(notAfterValueMax);
        CMS.debug("RandomizedValidityDefault populate  notAfterMax         = "+notAfterMax);
        CertificateValidity validity = 
                new CertificateValidity(notBeforeRandomized, notAfterRandomized);

        try {
            info.set(X509CertInfo.VALIDITY, validity);
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("RandomizedValidityDefault: populate " + e.toString());
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_INVALID_PROPERTY", X509CertInfo.VALIDITY));
        }
    }
}
