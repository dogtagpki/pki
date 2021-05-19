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
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.CAValidityDefault;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.RandomizedValidityDefault;
import com.netscape.cms.profile.def.UserValidityDefault;
import com.netscape.cms.profile.def.ValidityDefault;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the validity constraint.
 * It checks if the validity in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class ValidityConstraint extends EnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ValidityConstraint.class);

    public static final String CONFIG_RANGE = "range";
    public static final String CONFIG_RANGE_UNIT = "rangeUnit";
    public static final String CONFIG_NOT_BEFORE_GRACE_PERIOD = "notBeforeGracePeriod";
    public static final String CONFIG_CHECK_NOT_BEFORE = "notBeforeCheck";
    public static final String CONFIG_CHECK_NOT_AFTER = "notAfterCheck";
    public final static long SECS_IN_MS = 1000L;

    public ValidityConstraint() {
        super();
        addConfigName(CONFIG_RANGE);
        addConfigName(CONFIG_RANGE_UNIT);
        addConfigName(CONFIG_NOT_BEFORE_GRACE_PERIOD);
        addConfigName(CONFIG_CHECK_NOT_BEFORE);
        addConfigName(CONFIG_CHECK_NOT_AFTER);
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_RANGE) ||
                name.equals(CONFIG_NOT_BEFORE_GRACE_PERIOD)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", name));
            }
        }
        super.setConfig(name, value);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_RANGE)) {
            return new Descriptor(IDescriptor.INTEGER, null, "365",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_RANGE"));
        } else if (name.equals(CONFIG_RANGE_UNIT)) {
            return new Descriptor(IDescriptor.STRING, null, "day",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_RANGE_UNIT"));
        } else if (name.equals(CONFIG_NOT_BEFORE_GRACE_PERIOD)) {
            return new Descriptor(IDescriptor.INTEGER, null, "0",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_NOT_BEFORE_GRACE_PERIOD"));
        } else if (name.equals(CONFIG_CHECK_NOT_BEFORE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_CHECK_NOT_BEFORE"));
        } else if (name.equals(CONFIG_CHECK_NOT_AFTER)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VALIDITY_CHECK_NOT_AFTER"));
        }
        return null;
    }

    public int convertRangeUnit(String unit) throws Exception {

        if (unit.equals("year")) {
            return Calendar.YEAR;

        } else if (unit.equals("month")) {
            return Calendar.MONTH;

        } else if (unit.equals("day") || unit.equals("")) {
            return Calendar.DAY_OF_YEAR;

        } else if (unit.equals("hour")) {
            return Calendar.HOUR_OF_DAY;

        } else if (unit.equals("minute")) {
            return Calendar.MINUTE;

        } else {
            throw new Exception("Invalid range unit: " + unit);
        }
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    @Override
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {

        CertificateValidity v;
        try {
            v = (CertificateValidity) info.get(X509CertInfo.VALIDITY);
        } catch (Exception e) {
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_VALIDITY_NOT_FOUND"));
        }

        Date notBefore;
        try {
            notBefore = (Date) v.get(CertificateValidity.NOT_BEFORE);
            logger.debug("ValidityConstraint: not before: " + notBefore);
        } catch (IOException e) {
            logger.error("ValidityConstraint: not before not found: " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_VALIDITY_NOT_FOUND"));
        }

        Date notAfter;
        try {
            notAfter = (Date) v.get(CertificateValidity.NOT_AFTER);
            logger.debug("ValidityConstraint: not after: " + notAfter);
        } catch (IOException e) {
            logger.error("ValidityConstraint: not after not found: " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_VALIDITY_NOT_FOUND"));
        }

        if (notAfter.getTime() < notBefore.getTime()) {
            logger.debug("ValidityConstraint: notAfter (" + notAfter + ") < notBefore (" + notBefore + ")");
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_NOT_AFTER_BEFORE_NOT_BEFORE"));
        }

        String rangeStr = getConfig(CONFIG_RANGE, "365");
        logger.debug("ValidityConstraint: range: " + rangeStr);
        int range = Integer.parseInt(rangeStr);

        String rangeUnitStr = getConfig(CONFIG_RANGE_UNIT, "day");
        logger.debug("ValidityConstraint: range unit: " + rangeUnitStr);

        int rangeUnit;
        try {
            rangeUnit = convertRangeUnit(rangeUnitStr);
        } catch (Exception e) {
            logger.error("ValidityConstraint: invalid range unit: " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                    "CMS_PROFILE_VALIDITY_INVALID_RANGE_UNIT",
                    rangeUnitStr));
        }

        // calculate the end of validity range
        Calendar date = Calendar.getInstance();
        date.setTime(notBefore);
        date.add(rangeUnit, range);

        Date limit = date.getTime();
        logger.debug("ValidityConstraint: limit: " + limit);

        if (notAfter.after(limit)) {
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_VALIDITY_OUT_OF_RANGE",
                        notAfter.toString(), limit.toString()));
        }

        // 613828
        // The validity field shall specify a notBefore value
        // that does not precede the current time and a notAfter
        // value that does not precede the value specified in
        // notBefore (test can be automated; try entering violating
        // time values and check result).
        String notBeforeCheckStr = getConfig(CONFIG_CHECK_NOT_BEFORE);
        boolean notBeforeCheck;

        if (notBeforeCheckStr == null || notBeforeCheckStr.equals("")) {
            notBeforeCheckStr = "false";
        }
        notBeforeCheck = Boolean.valueOf(notBeforeCheckStr).booleanValue();

        String notAfterCheckStr = getConfig(CONFIG_CHECK_NOT_AFTER);
        boolean notAfterCheck;

        if (notAfterCheckStr == null || notAfterCheckStr.equals("")) {
            notAfterCheckStr = "false";
        }
        notAfterCheck = Boolean.valueOf(notAfterCheckStr).booleanValue();

        String notBeforeGracePeriodStr = getConfig(CONFIG_NOT_BEFORE_GRACE_PERIOD);
        if (notBeforeGracePeriodStr == null || notBeforeGracePeriodStr.equals("")) {
            notBeforeGracePeriodStr = "0";
        }
        long notBeforeGracePeriod = Long.parseLong(notBeforeGracePeriodStr) * SECS_IN_MS;

        Date current = new Date();
        if (notBeforeCheck) {
            if (notBefore.getTime() > (current.getTime() + notBeforeGracePeriod)) {
                logger.debug("ValidityConstraint: notBefore (" + notBefore + ") > current + " +
                          "gracePeriod (" + new Date(current.getTime() + notBeforeGracePeriod) + ")");
                throw new ERejectException(CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_NOT_BEFORE_AFTER_CURRENT"));
            }
        }
        if (notAfterCheck) {
            if (notAfter.getTime() < current.getTime()) {
                logger.debug("ValidityConstraint: notAfter (" + notAfter + ") <  current + (" + current + ")");
                throw new ERejectException(CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_NOT_AFTER_BEFORE_CURRENT"));
            }
        }
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_VALIDITY_TEXT", getConfig(CONFIG_RANGE));
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserValidityDefault)
            return true;
        if (def instanceof ValidityDefault)
            return true;
        if (def instanceof CAValidityDefault)
            return true;
        if (def instanceof RandomizedValidityDefault)
            return true;
        return false;
    }
}
