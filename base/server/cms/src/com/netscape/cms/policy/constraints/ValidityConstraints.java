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
package com.netscape.cms.policy.constraints;

import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateValidity;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * ValidityConstraints is a default rule for Enrollment and
 * Renewal that enforces minimum and maximum validity periods
 * and changes them if not met.
 *
 * Optionally the lead and lag times - i.e how far back into the
 * front or back the notBefore date could go in minutes can also
 * be specified.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public class ValidityConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected long mMinValidity;
    protected long mMaxValidity;
    protected long mLeadTime;
    protected long mLagTime;
    protected long mNotBeforeSkew;

    private final static String PROP_MIN_VALIDITY = "minValidity";
    private final static String PROP_MAX_VALIDITY = "maxValidity";
    private final static String PROP_LEAD_TIME = "leadTime";
    private final static String PROP_LAG_TIME = "lagTime";
    private final static String PROP_NOT_BEFORE_SKEW = "notBeforeSkew";
    public final static int DEF_MIN_VALIDITY = 180;
    public final static int DEF_MAX_VALIDITY = 730;
    public final static int DEF_LEAD_TIME = 10;
    public final static int DEF_LAG_TIME = 10;
    public final static int DEF_NOT_BEFORE_SKEW = 5;
    public final static long DAYS_TO_MS_FACTOR = 24L * 3600 * 1000;
    public final static long MINS_TO_MS_FACTOR = 60L * 1000;

    private final static Vector<String> defConfParams = new Vector<String>();

    static {
        defConfParams.addElement(PROP_MIN_VALIDITY + "=" +
                DEF_MIN_VALIDITY);
        defConfParams.addElement(PROP_MAX_VALIDITY + "=" +
                DEF_MAX_VALIDITY);
        defConfParams.addElement(PROP_LEAD_TIME + "=" +
                DEF_LEAD_TIME);
        defConfParams.addElement(PROP_LAG_TIME + "=" +
                DEF_LAG_TIME);
        defConfParams.addElement(PROP_NOT_BEFORE_SKEW + "=" +
                DEF_NOT_BEFORE_SKEW);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_MIN_VALIDITY + ";number;Minimum Validity time, in days",
                PROP_MAX_VALIDITY + ";number;Maximum Validity time, in days",
                PROP_LEAD_TIME + ";number;Number of minutes in the future a request's notBefore can be",
                PROP_LAG_TIME + ";number;NOT CURRENTLY IN USE",
                PROP_NOT_BEFORE_SKEW + ";number;Number of minutes a cert's notBefore should be in the past",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-validityconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Ensures that the user's requested validity period is " +
                        "acceptable. If not specified, as is usually the case, " +
                        "this policy will set the validity. See RFC 2459."
            };

        return params;

    }

    public ValidityConstraints() {
        NAME = "ValidityConstraints";
        DESC = "Enforces minimum and maximum validity constraints.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=ValidityConstraints ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.minValidity=30 ra.Policy.rule.<ruleName>.maxValidity=180
     * ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {

        // Get min and max validity in days and configure them.
        try {
            String val = config.getString(PROP_MIN_VALIDITY, null);

            if (val == null)
                mMinValidity = DEF_MIN_VALIDITY * DAYS_TO_MS_FACTOR;
            else
                mMinValidity = Long.parseLong(val) * DAYS_TO_MS_FACTOR;

            val = config.getString(PROP_MAX_VALIDITY, null);
            if (val == null)
                mMaxValidity = DEF_MAX_VALIDITY * DAYS_TO_MS_FACTOR;
            else
                mMaxValidity = Long.parseLong(val) * DAYS_TO_MS_FACTOR;

            val = config.getString(PROP_LEAD_TIME, null);
            if (val != null)
                mLeadTime = Long.parseLong(val) * MINS_TO_MS_FACTOR;
            else
                mLeadTime = DEF_LEAD_TIME * MINS_TO_MS_FACTOR;

            val = config.getString(PROP_LAG_TIME, null);
            if (val != null)
                mLagTime = Long.parseLong(val) * MINS_TO_MS_FACTOR;
            else
                mLagTime = DEF_LAG_TIME * MINS_TO_MS_FACTOR;

            val = config.getString(PROP_NOT_BEFORE_SKEW, null);
            if (val != null)
                mNotBeforeSkew = Long.parseLong(val) * MINS_TO_MS_FACTOR;
            else
                mNotBeforeSkew = DEF_NOT_BEFORE_SKEW * MINS_TO_MS_FACTOR;
        } catch (Exception e) {
            // e.printStackTrace();
            String[] params = { getInstanceName(), e.toString() };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG", params));
        }
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

        PolicyResult result = PolicyResult.ACCEPTED;

        try {
            // Get the certificate info from the request
            //X509CertInfo certInfo[] = (X509CertInfo[])
            //    req.get(IRequest.CERT_INFO);
            X509CertInfo certInfo[] = req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // There should be a certificate info set.
            if (certInfo == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // Else check if validity is within the limit
            for (int i = 0; i < certInfo.length; i++) {
                CertificateValidity validity = (CertificateValidity)
                        certInfo[i].get(X509CertInfo.VALIDITY);

                Date notBefore = null, notAfter = null;

                if (validity != null) {
                    notBefore = (Date)
                            validity.get(CertificateValidity.NOT_BEFORE);
                    notAfter = (Date)
                            validity.get(CertificateValidity.NOT_AFTER);
                }

                // If no validity is supplied yet, make one.  The default
                // validity is supposed to pass the following checks, so
                // bypass further checking.
                // (date = 0 is hack for serialization)

                if (validity == null ||
                        (notBefore.getTime() == 0 && notAfter.getTime() == 0)) {
                    certInfo[i].set(X509CertInfo.VALIDITY,
                            makeDefaultValidity(req));
                    continue;
                }

                Date now = CMS.getCurrentDate();

                if (notBefore.getTime() > (now.getTime() + mLeadTime)) {
                    setError(req, CMS.getUserMessage("CMS_POLICY_INVALID_BEGIN_TIME",
                            getInstanceName()), "");
                    result = PolicyResult.REJECTED;
                }
                if ((notAfter.getTime() - notBefore.getTime()) > mMaxValidity) {
                    String params[] = { getInstanceName(),
                            String.valueOf(
                                    ((notAfter.getTime() - notBefore.getTime()) / DAYS_TO_MS_FACTOR)),
                            String.valueOf(mMaxValidity / DAYS_TO_MS_FACTOR) };

                    setError(req, CMS.getUserMessage("CMS_POLICY_MORE_THAN_MAX_VALIDITY", params), "");
                    result = PolicyResult.REJECTED;
                }
                if ((notAfter.getTime() - notBefore.getTime()) < mMinValidity) {
                    String params[] = { getInstanceName(),
                            String.valueOf(
                                    ((notAfter.getTime() - notBefore.getTime()) / DAYS_TO_MS_FACTOR)),
                            String.valueOf(mMinValidity / DAYS_TO_MS_FACTOR) };

                    setError(req, CMS.getUserMessage("CMS_POLICY_LESS_THAN_MIN_VALIDITY", params), "");
                    result = PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            // e.printStackTrace();
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    params), "");
            result = PolicyResult.REJECTED;
        }
        return result;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<String>();

        confParams.addElement(PROP_MIN_VALIDITY + "=" +
                mMinValidity / DAYS_TO_MS_FACTOR);
        confParams.addElement(PROP_MAX_VALIDITY + "=" +
                mMaxValidity / DAYS_TO_MS_FACTOR);
        confParams.addElement(PROP_LEAD_TIME + "="
                + mLeadTime / MINS_TO_MS_FACTOR);
        confParams.addElement(PROP_LAG_TIME + "=" +
                mLagTime / MINS_TO_MS_FACTOR);
        confParams.addElement(PROP_NOT_BEFORE_SKEW + "=" +
                mNotBeforeSkew / MINS_TO_MS_FACTOR);
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return defConfParams;
    }

    /**
     * Create a default validity value for a request
     *
     * This code can be easily overridden in a derived class, if the
     * calculations here aren't accepatble.
     *
     * TODO: it might be good to base this calculation on the creation
     * time of the request.
     */
    protected CertificateValidity makeDefaultValidity(IRequest req) {
        long now = roundTimeToSecond((CMS.getCurrentDate()).getTime());

        // We will set the max duration as the default validity.
        long notBeforeTime = now - mNotBeforeSkew;
        Date notBefore = new Date(notBeforeTime);
        Date notAfter = new Date(notBeforeTime + mMaxValidity);

        return new CertificateValidity(notBefore, notAfter);
    }

    /**
     * convert a millisecond resolution time into one with 1 second
     * resolution. Most times in certificates are storage at 1
     * second resolution, so its better if we deal with things at
     * that level.
     */
    protected long roundTimeToSecond(long input) {
        return (input / 1000) * 1000;
    }
}
