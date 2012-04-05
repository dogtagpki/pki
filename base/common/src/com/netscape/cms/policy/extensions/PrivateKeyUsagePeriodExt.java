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
package com.netscape.cms.policy.extensions;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.PrivateKeyUsageExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * PrivateKeyUsagePeriod Identifier Extension policy.
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
public class PrivateKeyUsagePeriodExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    private final static String PROP_NOT_BEFORE = "notBefore";
    private final static String PROP_NOT_AFTER = "notAfter";
    protected static final String PROP_IS_CRITICAL = "critical";

    // 6 months roughly
    private final static long defDuration = 60L * 60 * 24 * 180 * 1000;

    private static final String DATE_PATTERN = "MM/dd/yyyy";
    static SimpleDateFormat formatter = new SimpleDateFormat(DATE_PATTERN);
    private static Date now = CMS.getCurrentDate();
    private static Date six_months = new Date(now.getTime() + defDuration);

    public static final String DEFAULT_NOT_BEFORE = formatter.format(now);
    public static final String DEFAULT_NOT_AFTER = formatter.format(six_months);

    // PKIX specifies the that the extension SHOULD NOT be critical
    public static final boolean DEFAULT_CRITICALITY = false;

    protected String mNotBefore;
    protected String mNotAfter;
    protected boolean mCritical;

    private static Vector<String> defaultParams;

    static {

        formatter.setLenient(false);

        defaultParams = new Vector<String>();
        defaultParams.addElement(PROP_IS_CRITICAL + "=" + DEFAULT_CRITICALITY);
        defaultParams.addElement(PROP_NOT_BEFORE + "=" + DEFAULT_NOT_BEFORE);
        defaultParams.addElement(PROP_NOT_AFTER + "=" + DEFAULT_NOT_AFTER);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_IS_CRITICAL + ";boolean;RFC 2459 recommendation: The profile " +
                        "recommends against the use of this extension. CAs " +
                        "conforming to the profile MUST NOT generate certs with " +
                        "critical private key usage period extensions.",
                PROP_NOT_BEFORE + ";string; Date before which the Private Key is invalid.",
                PROP_NOT_AFTER + ";string; Date after which the Private Key is invalid.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-privatekeyusageperiod",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds (deprecated) Private Key Usage Period Extension. " +
                        "Defined in RFC 2459 (4.2.1.4)"
            };

        return params;
    }

    /**
     * Adds the private key usage extension to all certs.
     */
    public PrivateKeyUsagePeriodExt() {
        NAME = "PrivateKeyUsagePeriodExt";
        DESC = "Sets Private Key Usage Extension for a certificate";
    }

    /**
     * Initializes this policy rule.
     * ra.Policy.rule.<ruleName>.implName=PrivateKeyUsageExtension
     * ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.notBefore=30
     * ra.Policy.rule.<ruleName>.notAfter=180
     * ra.Policy.rule.<ruleName>.critical=false
     * ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        try {
            // Get params.
            mNotBefore = config.getString(PROP_NOT_BEFORE, null);
            mNotAfter = config.getString(PROP_NOT_AFTER, null);
            mCritical = config.getBoolean(PROP_IS_CRITICAL, false);

            // Check the parameter formats for errors
            formatter.format(formatter.parse(mNotBefore.trim()));
            formatter.format(formatter.parse(mNotAfter.trim()));
        } catch (Exception e) {
            // e.printStackTrace();
            Object[] params = { getInstanceName(), e };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG"), params);
        }

    }

    /**
     * Adds a private key usage extension if none exists.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

        // get cert info.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        // get private key usage extension from cert info if any.
        CertificateExtensions extensions = null;
        PrivateKeyUsageExtension ext = null;

        try {
            // get subject key id extension if any.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
            // no extensions or subject key identifier extension.
        } catch (CertificateException e) {
            // no extensions or subject key identifier extension.
        }

        if (extensions == null) {
            extensions = new CertificateExtensions();
        } else {
            // remove any previously computed version of the extension
            try {
                extensions.delete(PrivateKeyUsageExtension.NAME);

            } catch (IOException e) {
            }

        }

        try {
            ext = new PrivateKeyUsageExtension(
                        formatter.parse(mNotBefore),
                        formatter.parse(mNotAfter));
            certInfo.set(X509CertInfo.VERSION,
                    new CertificateVersion(CertificateVersion.V3));
            extensions.set(PrivateKeyUsageExtension.NAME, ext);
        } catch (Exception e) {
            if (e instanceof RuntimeException)
                throw (RuntimeException) e;
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_CREATE_PRIVATE_KEY_EXT", e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR"), NAME);
            return PolicyResult.REJECTED;
        }
        return PolicyResult.ACCEPTED;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return Empty Vector since this policy has no configuration parameters.
     *         for this policy instance.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_IS_CRITICAL + "=" + mCritical);
        params.addElement(PROP_NOT_BEFORE + "=" + mNotBefore);
        params.addElement(PROP_NOT_AFTER + "=" + mNotAfter);
        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return Empty Vector since this policy implementation has no
     *         configuration parameters.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_IS_CRITICAL + "=" + DEFAULT_CRITICALITY);
        defParams.addElement(PROP_NOT_BEFORE + "=" + DEFAULT_NOT_BEFORE);
        defParams.addElement(PROP_NOT_AFTER + "=" + DEFAULT_NOT_AFTER);
        return defParams;
    }
}
