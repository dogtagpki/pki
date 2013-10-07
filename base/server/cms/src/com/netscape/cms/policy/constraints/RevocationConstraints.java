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
import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IRevocationPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Whether to allow revocation of an expired cert.
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
public class RevocationConstraints extends APolicyRule
        implements IRevocationPolicy, IExtendedPluginInfo {
    private static final String PROP_ALLOW_EXPIRED_CERTS = "allowExpiredCerts";
    private static final String PROP_ALLOW_ON_HOLD = "allowOnHold";

    private boolean mAllowExpiredCerts = true;
    private boolean mAllowOnHold = true;

    private final static Vector<String> defConfParams = new Vector<String>();
    static {
        defConfParams.addElement(PROP_ALLOW_EXPIRED_CERTS + "=" + true);
        defConfParams.addElement(PROP_ALLOW_ON_HOLD + "=" + true);
    }

    public RevocationConstraints() {
        NAME = "RevocationConstraints";
        DESC = "Whether to allow revocation of expired certs and on-hold.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_ALLOW_EXPIRED_CERTS + ";boolean;Allow a user to revoke an already-expired certificate",
                PROP_ALLOW_ON_HOLD + ";boolean;Allow a user to set reason to On-Hold",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-revocationconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Allow administrator to decide policy on whether to allow " +
                        "recovation of expired certificates" +
                        "and set reason to On-Hold"

        };

        return params;

    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=ValidityConstraints ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.allowExpiredCerts=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {
        // Get min and max validity in days and onfigure them.
        try {
            mAllowExpiredCerts =
                    config.getBoolean(PROP_ALLOW_EXPIRED_CERTS, true);
            mAllowOnHold =
                    config.getBoolean(PROP_ALLOW_ON_HOLD, true);
        } catch (EBaseException e) {
            // never happen.
        }

        CMS.debug("RevocationConstraints: allow expired certs " + mAllowExpiredCerts);
        CMS.debug("RevocationConstraints: allow on hold " + mAllowOnHold);
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        CMS.debug("RevocationConstraints: apply begins");
        if (req.getExtDataInInteger(IRequest.REVOKED_REASON) == null) {
            CMS.debug("RevocationConstraints: apply: no revocationReason found in request");
            return PolicyResult.REJECTED;
        }
        RevocationReason rr = RevocationReason.fromInt(
                req.getExtDataInInteger(IRequest.REVOKED_REASON).intValue());

        if (!mAllowOnHold && (rr != null)) {
            int reason = rr.toInt();

            if (reason == RevocationReason.CERTIFICATE_HOLD.toInt()) {
                String params[] = { getInstanceName() };

                setError(req, CMS.getUserMessage("CMS_POLICY_NO_ON_HOLD_ALLOWED", params), "");
                return PolicyResult.REJECTED;
            }
        }

        if (mAllowExpiredCerts)
            // nothing to check.
            return PolicyResult.ACCEPTED;

        PolicyResult result = PolicyResult.ACCEPTED;

        try {
            // Get the certificates being renwed.
            X509CertImpl[] oldCerts =
                    req.getExtDataInCertArray(IRequest.OLD_CERTS);

            if (oldCerts == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_OLD_CERT"),
                        getInstanceName());
                return PolicyResult.REJECTED;
            }

            // check if each cert to be renewed is expired.
            for (int i = 0; i < oldCerts.length; i++) {
                X509CertInfo oldCertInfo = (X509CertInfo)
                        oldCerts[i].get(
                                X509CertImpl.NAME + "." + X509CertImpl.INFO);
                CertificateValidity oldValidity = (CertificateValidity)
                        oldCertInfo.get(X509CertInfo.VALIDITY);
                Date notAfter = (Date)
                        oldValidity.get(CertificateValidity.NOT_AFTER);

                // Is the Certificate still valid?
                Date now = CMS.getCurrentDate();

                if (notAfter.before(now)) {
                    String params[] = { getInstanceName() };

                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_CANNOT_REVOKE_EXPIRED_CERTS",
                                    params), "");
                    result = PolicyResult.REJECTED;
                    break;
                }
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

        confParams.addElement(
                PROP_ALLOW_EXPIRED_CERTS + "=" + mAllowExpiredCerts);
        confParams.addElement(
                PROP_ALLOW_ON_HOLD + "=" + mAllowOnHold);
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
}
