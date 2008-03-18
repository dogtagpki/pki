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


import java.util.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import netscape.security.x509.*;
import com.netscape.cms.policy.APolicyRule;


/**
 * Whether to allow revocation of an expired cert.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class RevocationConstraints extends APolicyRule
    implements IRevocationPolicy, IExtendedPluginInfo {
    private static final String PROP_ALLOW_EXPIRED_CERTS = "allowExpiredCerts";
    private static final String PROP_ALLOW_ON_HOLD = "allowOnHold";

    private boolean mAllowExpiredCerts = true;
    private boolean mAllowOnHold = true;

    private final static Vector defConfParams = new Vector();
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
     *      ra.Policy.rule.<ruleName>.implName=ValidityConstraints
     *      ra.Policy.rule.<ruleName>.enable=true
     *      ra.Policy.rule.<ruleName>.allowExpiredCerts=true
     *
     * @param config	The config store reference
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
     * @param req	The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
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
                CertificateValidity  oldValidity = (CertificateValidity)
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
            String params[] = {getInstanceName(), e.toString()};

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
    public Vector getInstanceParams() {
        Vector confParams = new Vector();

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
    public Vector getDefaultParams() {
        return defConfParams;
    }
}
