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

import java.math.BigInteger;
import java.util.Date;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cmscore.apps.CMS;

/**
 * This class supports renewal grace period, which has two
 * parameters: graceBefore and graceAfter
 *
 * @author Christina Fu
 * @version $Revision$, $Date$
 */
public class RenewGracePeriodConstraint extends EnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RenewGracePeriodConstraint.class);

    // for renewal: # of days before the orig cert expiration date
    public static final String CONFIG_RENEW_GRACE_BEFORE = "renewal.graceBefore";
    // for renewal: # of days after the orig cert expiration date
    public static final String CONFIG_RENEW_GRACE_AFTER = "renewal.graceAfter";

    public RenewGracePeriodConstraint() {
        super();
        addConfigName(CONFIG_RENEW_GRACE_BEFORE);
        addConfigName(CONFIG_RENEW_GRACE_AFTER);
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_RENEW_GRACE_BEFORE) ||
                name.equals(CONFIG_RENEW_GRACE_AFTER)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_RENEW_GRACE_BEFORE + " or " + CONFIG_RENEW_GRACE_AFTER));
            }
        }
        super.setConfig(name, value);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_RENEW_GRACE_BEFORE)) {
            return new Descriptor(IDescriptor.INTEGER, null, "30",
                    CMS.getUserMessage(locale, "CMS_PROFILE_RENEW_GRACE_BEFORE"));
        } else if (name.equals(CONFIG_RENEW_GRACE_AFTER)) {
            return new Descriptor(IDescriptor.INTEGER, null, "30",
                    CMS.getUserMessage(locale, "CMS_PROFILE_RENEW_GRACE_AFTER"));
        }
        return null;
    }

    @Override
    public void validate(IRequest req, X509CertInfo info)
            throws ERejectException {
        String method = "RenewGracePeriodConstraint: validate: ";
        String msg = "";

        String origExpDate_s = req.getExtDataInString("origNotAfter");
        if (origExpDate_s == null) { // probably not for renewal
            logger.debug(method + " original cert expiration date not found...return without validation");
            return;
        } else { //should occur when it's renewal
            logger.debug(method + " original cert expiration date found... validating");
        }
        BigInteger origExpDate_BI = new BigInteger(origExpDate_s);
        Date origExpDate = new Date(origExpDate_BI.longValue());
        String renew_grace_before_s = getConfig(CONFIG_RENEW_GRACE_BEFORE);
        String renew_grace_after_s = getConfig(CONFIG_RENEW_GRACE_AFTER);
        int renew_grace_before = 0;
        int renew_grace_after = 0;
        BigInteger renew_grace_before_BI = new BigInteger(renew_grace_before_s);
        BigInteger renew_grace_after_BI = new BigInteger(renew_grace_after_s);

        // -1 means no limit
        if (renew_grace_before_s == "")
            renew_grace_before = -1;
        else
            renew_grace_before = Integer.parseInt(renew_grace_before_s);

        if (renew_grace_after_s == "")
            renew_grace_after = -1;
        else
            renew_grace_after = Integer.parseInt(renew_grace_after_s);

        if (renew_grace_before > 0)
            renew_grace_before_BI = renew_grace_before_BI.multiply(BigInteger.valueOf(1000 * 86400));
        if (renew_grace_after > 0)
            renew_grace_after_BI = renew_grace_after_BI.multiply(BigInteger.valueOf(1000 * 86400));

        Date current = new Date();
        long millisDiff = origExpDate.getTime() - current.getTime();
        logger.debug(method + " millisDiff="
                + millisDiff + " origExpDate=" + origExpDate.getTime() + " current=" + current.getTime());

        /*
         * "days", if positive, has to be less than renew_grace_before
         * "days", if negative, means already past expiration date,
         *     (abs value) has to be less than renew_grace_after
         * if renew_grace_before or renew_grace_after are negative
         *    the one with negative value is ignored
         */
        if (millisDiff >= 0) {
            if ((renew_grace_before > 0) && (millisDiff > renew_grace_before_BI.longValue())) {
                msg = renew_grace_before + " days before and " +
                        renew_grace_after + " days after original cert expiration date";
                throw new ERejectException(CMS.getUserMessage(getLocale(req),
                        "CMS_PROFILE_RENEW_OUTSIDE_GRACE_PERIOD", msg));
            }
        } else {
            if ((renew_grace_after > 0) && ((0 - millisDiff) > renew_grace_after_BI.longValue())) {
                msg = renew_grace_before + " days before and " +
                        renew_grace_after + " days after original cert expiration date";
                throw new ERejectException(CMS.getUserMessage(getLocale(req),
                        "CMS_PROFILE_RENEW_OUTSIDE_GRACE_PERIOD", msg));
            }
        }
    }

    @Override
    public String getText(Locale locale) {
        String renew_grace_before_s = getConfig(CONFIG_RENEW_GRACE_BEFORE);
        String renew_grace_after_s = getConfig(CONFIG_RENEW_GRACE_AFTER);
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_VALIDITY_TEXT",
                        renew_grace_before_s + " days before and " +
                                renew_grace_after_s + " days after original cert expiration date");
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        return false;
    }
}
