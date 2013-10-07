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
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IRenewalPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;
import com.netscape.cmsutil.util.Utils;

/**
 * RenewalValidityConstraints is a default rule for Certificate
 * Renewal. This policy enforces the no of days before which a
 * currently active certificate can be renewed and sets new validity
 * period for the renewed certificate starting from the the ending
 * period in the old certificate.
 *
 * The main parameters are:
 *
 * The renewal leadtime in days: - i.e how many days before the
 * expiry of the current certificate can one request the renewal.
 * min and max validity duration.
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
public class RenewalValidityConstraints extends APolicyRule
        implements IRenewalPolicy, IExtendedPluginInfo {
    private long mMinValidity;
    private long mMaxValidity;
    private long mRenewalInterval;

    private final static String PROP_MIN_VALIDITY = "minValidity";
    private final static String PROP_MAX_VALIDITY = "maxValidity";
    private final static String PROP_RENEWAL_INTERVAL = "renewalInterval";
    public final static int DEF_MIN_VALIDITY = 180;
    public final static int DEF_MAX_VALIDITY = 730;
    public final static long DEF_RENEWAL_INTERVAL = 15;
    public final static long DAYS_TO_MS_FACTOR = 24L * 3600 * 1000;
    public static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----\n";
    public static final String CERT_TRAILER = "-----END CERTIFICATE-----\n";

    private final static Vector<String> defConfParams = new Vector<String>();

    static {
        defConfParams.addElement(PROP_MIN_VALIDITY + "=" +
                DEF_MIN_VALIDITY);
        defConfParams.addElement(PROP_MAX_VALIDITY + "=" +
                DEF_MAX_VALIDITY);
        defConfParams.addElement(PROP_RENEWAL_INTERVAL + "=" +
                DEF_RENEWAL_INTERVAL);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_MIN_VALIDITY
                        + ";number;Specifies the minimum validity period, in days, for renewed certificates.",
                PROP_MAX_VALIDITY
                        + ";number;Specifies the maximum validity period, in days, for renewed certificates.",
                PROP_RENEWAL_INTERVAL
                        + ";number;Specifies how many days before its expiration that a certificate can be renewed.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-renewalvalidityconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Reject renewal request if the certificate is too far " +
                        "before it's expiry date"
        };

        return params;

    }

    public RenewalValidityConstraints() {
        NAME = "RenewalValidityConstraints";
        DESC = "Enforces minimum and maximum validity and renewal interval for certificate renewal.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=ValidityConstraints ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.minValidity=30 ra.Policy.rule.<ruleName>.maxValidity=180
     * ra.Policy.rule.<ruleName>.renewalInterval=15 ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {

        // Get min and max validity in days and onfigure them.
        try {
            String val = config.getString(PROP_MIN_VALIDITY, null);

            if (val == null)
                mMinValidity = DEF_MIN_VALIDITY * DAYS_TO_MS_FACTOR;
            else
                mMinValidity = Long.parseLong(val) * DAYS_TO_MS_FACTOR;

            val = config.getString(PROP_MAX_VALIDITY, null);
            if (val == null)
                mMaxValidity = DEF_MAX_VALIDITY * DAYS_TO_MS_FACTOR;
            else {
                mMaxValidity = Long.parseLong(val) * DAYS_TO_MS_FACTOR;
            }
            val = config.getString(PROP_RENEWAL_INTERVAL, null);
            if (val == null)
                mRenewalInterval = DEF_RENEWAL_INTERVAL * DAYS_TO_MS_FACTOR;
            else {
                mRenewalInterval = Long.parseLong(val) * DAYS_TO_MS_FACTOR;
            }

            // minValidity can't be bigger than maxValidity.
            if (mMinValidity > mMaxValidity) {
                String params[] = { getInstanceName(),
                        String.valueOf(mMinValidity / DAYS_TO_MS_FACTOR),
                        String.valueOf(mMaxValidity / DAYS_TO_MS_FACTOR) };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_RENEWAL_MIN_MAX", params));
            }

            // Renewal interval can't be more than maxValidity.
            if (mRenewalInterval > mMaxValidity) {
                String params[] = { getInstanceName(),
                        String.valueOf(mRenewalInterval / DAYS_TO_MS_FACTOR),
                        String.valueOf(mMaxValidity / DAYS_TO_MS_FACTOR) };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_RENEWAL_INTERVAL", params));
            }
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

        if (agentApproved(req))
            return result;

        try {
            // Get the certificate info from the request
            X509CertInfo certInfo[] =
                    req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // Get the certificates being renwed.
            X509CertImpl currentCerts[] =
                    req.getExtDataInCertArray(IRequest.OLD_CERTS);

            // Both certificate info and current certs should be set
            if (certInfo == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }
            if (currentCerts == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_OLD_CERT",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }
            if (certInfo.length != currentCerts.length) {
                setError(req, CMS.getUserMessage("CMS_POLICY_MISMATCHED_CERTINFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // Else check if the renewal interval is okay and then
            // set the validity.
            for (int i = 0; i < certInfo.length; i++) {
                X509CertInfo oldCertInfo = (X509CertInfo)
                        currentCerts[i].get(X509CertImpl.NAME +
                                "." + X509CertImpl.INFO);
                CertificateValidity oldValidity = (CertificateValidity)
                        oldCertInfo.get(X509CertInfo.VALIDITY);
                Date notAfter = (Date)
                        oldValidity.get(CertificateValidity.NOT_AFTER);

                // Is the Certificate still valid?
                Date now = CMS.getCurrentDate();

                if (notAfter.after(now)) {
                    // Check if the renewal interval is alright.
                    long interval = notAfter.getTime() - now.getTime();

                    if (interval > mRenewalInterval) {
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_LONG_RENEWAL_LEAD_TIME",
                                        getInstanceName(),
                                        String.valueOf(mRenewalInterval / DAYS_TO_MS_FACTOR)), "");
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_EXISTING_CERT_DETAILS",
                                        getInstanceName(),
                                        getCertDetails(req, currentCerts[i])), "");

                        result = PolicyResult.REJECTED;
                        setDummyValidity(certInfo[i]);
                        continue;
                    }
                }

                // Else compute new  validity.
                Date renewedNotBef = notAfter;
                Date renewedNotAfter = new Date(notAfter.getTime() +
                        mMaxValidity);

                // If the new notAfter is within renewal interval days from
                // today or already expired, set the notBefore to today.
                if (renewedNotAfter.before(now) ||
                        (renewedNotAfter.getTime() - now.getTime()) <=
                        mRenewalInterval) {
                    renewedNotBef = now;
                    renewedNotAfter = new Date(now.getTime() +
                                mMaxValidity);
                }
                CertificateValidity newValidity =
                        new CertificateValidity(renewedNotBef, renewedNotAfter);

                certInfo[i].set(X509CertInfo.VALIDITY, newValidity);
            }
        } catch (Exception e) {
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR", params), "");
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
        confParams.addElement(PROP_RENEWAL_INTERVAL + "=" +
                mRenewalInterval / DAYS_TO_MS_FACTOR);
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

    // Set dummy validity field so the request will serialize properly
    private void setDummyValidity(X509CertInfo certInfo) {
        try {
            certInfo.set(X509CertInfo.VALIDITY,
                    new CertificateValidity(CMS.getCurrentDate(), new Date()));
        } catch (Exception e) {
        }
    }

    private String getCertDetails(IRequest req, X509CertImpl cert) {
        StringBuffer sb = new StringBuffer();

        sb.append("\n");
        sb.append("Serial No: " + cert.getSerialNumber().toString(16));
        sb.append("\n");
        sb.append("Validity: " + cert.getNotBefore().toString() +
                " - " + cert.getNotAfter().toString());
        sb.append("\n");
        String certType = req.getExtDataInString(IRequest.CERT_TYPE);

        if (certType == null)
            certType = IRequest.SERVER_CERT;
        if (certType.equals(IRequest.CLIENT_CERT)) {

            /***
             * Take this our - URL formulation hard to do here.
             * sb.append("Use the following url with your CA/RA gateway spec to download the certificate.");
             * sb.append("\n");
             * sb.append("/query/certImport?op=displayByserial&serialNumber=");
             * sb.append(cert.getSerialNumber().toString(16));
             ***/
            sb.append("\n");
        } else {
            sb.append("Certificate Content is as follows:");
            sb.append("\n");
            try {
                byte[] ba = cert.getEncoded();
                String encodedCert = Utils.base64encode(ba);

                sb.append(CERT_HEADER + encodedCert + CERT_TRAILER);
            } catch (Exception e) {
                //throw new AssertionException(e.toString());
            }
        }
        return sb.toString();
    }
}
