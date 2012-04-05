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
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import netscape.security.extensions.CertificateRenewalWindowExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Certificate Renewal Window Extension Policy
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
public class CertificateRenewalWindowExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    protected static final String PROP_END_TIME = "relativeEndTime";
    protected static final String PROP_BEGIN_TIME = "relativeBeginTime";
    protected static final String PROP_CRITICAL = "critical";

    protected boolean mCritical;
    protected String mBeginTime;
    protected String mEndTime;

    /**
     * Adds the Netscape comment in the end-entity certificates or
     * CA certificates. The policy is set to be non-critical with the
     * provided OID.
     */
    public CertificateRenewalWindowExt() {
        NAME = "CertificateRenewalWindowExt";
        DESC = "Sets non-critical Certificate Renewal Window extension in certs";
    }

    /**
     * Initializes this policy rule.
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mCritical = config.getBoolean(PROP_CRITICAL, false);
        mBeginTime = config.getString(PROP_BEGIN_TIME, null);
        mEndTime = config.getString(PROP_END_TIME, null);

    }

    /**
     * Applies the policy on the given Request.
     * <p>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        // get cert info.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult r = applyCert(req, ci[i]);

            if (r == PolicyResult.REJECTED)
                return r;
        }
        return res;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        CertificateExtensions extensions = null;

        try {
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
        } catch (CertificateException e) {
        }

        if (extensions == null) {
            extensions = new CertificateExtensions();
            try {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } catch (Exception e) {
            }
        } else {
            // remove any previously computed version of the extension
            try {
                extensions.delete(CertificateRenewalWindowExtension.NAME);

            } catch (IOException e) {
                // this is the hack: for some reason, the key which is the name
                // of the policy has been converted into the OID
                try {
                    extensions.delete("2.16.840.1.113730.1.15");
                } catch (IOException ee) {
                }
            }
        }

        try {
            Date now = CMS.getCurrentDate();
            CertificateRenewalWindowExtension crwExt = null;

            if (mEndTime == null || mEndTime.equals("")) {
                crwExt = new CertificateRenewalWindowExtension(
                            mCritical,
                            getDateValue(now, mBeginTime),
                            null);
            } else {
                crwExt = new CertificateRenewalWindowExtension(
                            mCritical,
                            getDateValue(now, mBeginTime),
                            getDateValue(now, mEndTime));
            }
            extensions.set(CertificateRenewalWindowExtension.NAME,
                    crwExt);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_CERTIFICATE_POLICIES_1", NAME));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR"), NAME);
            return PolicyResult.REJECTED;
        }
        return PolicyResult.ACCEPTED;
    }

    public Date getDateValue(Date relativeFrom, String s) {
        long time;

        if (s.endsWith("s")) {
            time = 1000 * Long.parseLong(s.substring(0,
                            s.length() - 1));
        } else if (s.endsWith("m")) {
            time = 60 * 1000 * Long.parseLong(s.substring(0,
                            s.length() - 1));
        } else if (s.endsWith("h")) {
            time = 60 * 60 * 1000 * Long.parseLong(s.substring(0,
                            s.length() - 1));
        } else if (s.endsWith("D")) {
            time = 24 * 60 * 60 * 1000 * Long.parseLong(
                        s.substring(0, s.length() - 1));
        } else if (s.endsWith("M")) {
            time = 30 * 60 * 60 * 1000 * Long.parseLong(
                        s.substring(0, s.length() - 1));
        } else {
            time = 1000 * Long.parseLong(s);
        }

        return new Date(relativeFrom.getTime() + time);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;Netscape recommendation: non-critical.",
                PROP_BEGIN_TIME
                        + ";string;Start Time in seconds (Relative to the time of issuance). Optionally, time unit (s - seconds, m - minutes, h - hours, D - days, M - months) can be specified right after the value. For example, 5 days can be expressed as 5D.",
                PROP_END_TIME
                        + ";string;End Time in seconds (Optional, Relative to the time of issuance). Optionally, time unit (s - seconds, m - minutes, h - hours, D - days, M - months) can be specified right after the value. For example, 5 days can be expressed as 5D.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-certificaterenewalwindow",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds 'Certificate Renewal Window' extension. See manual"
        };

        return params;

    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_CRITICAL + "=" + mCritical);
        if (mBeginTime == null) {
            params.addElement(PROP_BEGIN_TIME + "=");
        } else {
            params.addElement(PROP_BEGIN_TIME + "=" + mBeginTime);
        }
        if (mEndTime == null) {
            params.addElement(PROP_END_TIME + "=");
        } else {
            params.addElement(PROP_END_TIME + "=" + mEndTime);
        }
        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");
        defParams.addElement(PROP_BEGIN_TIME + "=");
        defParams.addElement(PROP_END_TIME + "=");
        return defParams;
    }
}
