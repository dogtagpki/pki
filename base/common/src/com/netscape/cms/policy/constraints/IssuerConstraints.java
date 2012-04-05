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

import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
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
 * IssuerConstraints is a rule for restricting the issuers of the
 * certificates used for certificate-based enrollments.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$ $Date$
 */
public class IssuerConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    private final static String PROP_ISSUER_DN = "issuerDN";
    private static final String CLIENT_ISSUER = "clientIssuer";
    private X500Name mIssuerDN = null;
    private String mIssuerDNString;

    /**
     * checks the issuer of the ssl client-auth cert. Only one issuer
     * is allowed for now
     */
    public IssuerConstraints() {
        NAME = "IssuerConstraints";
        DESC = "Checks to see if the Issuer is one allowed";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_ISSUER_DN
                        + ";string;Subject DN of the Issuer. The IssuerDN of the authenticating cert must match what's specified here",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-issuerconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Rejects the request if the issuer in the certificate is" +
                        "not of the one specified"
        };

        return params;

    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {
        try {
            mIssuerDNString = config.getString(PROP_ISSUER_DN, null);
            if ((mIssuerDNString != null) &&
                    !mIssuerDNString.equals("")) {
                mIssuerDN = new X500Name(mIssuerDNString);
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    NAME + CMS.getLogMessage("CA_GET_ISSUER_NAME_FAILED"));

            String[] params = { getInstanceName(), e.toString() };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG", params));
        }
        CMS.debug(
                NAME + ": init() done");
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

        if (mIssuerDN == null)
            return result;

        try {
            String clientIssuerDN = req.getExtDataInString(CLIENT_ISSUER);

            if (clientIssuerDN != null) {
                X500Name ci_name = new X500Name(clientIssuerDN);

                if (!ci_name.equals(mIssuerDN)) {
                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_INVALID_ISSUER",
                                    getInstanceName()), "");
                    result = PolicyResult.REJECTED;
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CA_GET_ISSUER_NAME_FAILED"));
                    CMS.debug(
                            NAME + ": apply() - issuerDN mismatch: client issuerDN = " + clientIssuerDN
                                    + "; expected issuerDN = " + mIssuerDNString);
                }
            } else {

                // Get the certificate info from the request
                X509CertInfo certInfo[] =
                        req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

                if (certInfo == null) {
                    log(ILogger.LL_FAILURE,
                            NAME + ": apply() - missing certInfo");
                    setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                            getInstanceName()), "");
                    return PolicyResult.REJECTED;
                }

                for (int i = 0; i < certInfo.length; i++) {
                    String oldIssuer = certInfo[i].get(X509CertInfo.ISSUER).toString();

                    if (oldIssuer == null) {
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_CLIENT_ISSUER_NOT_FOUND",
                                        getInstanceName()), "");
                        result = PolicyResult.REJECTED;
                        log(ILogger.LL_FAILURE,
                                NAME + ": apply() - client issuerDN not found");
                    }
                    X500Name oi_name = new X500Name(oldIssuer);

                    if (!oi_name.equals(mIssuerDN)) {
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_INVALID_ISSUER",
                                        getInstanceName()), "");
                        result = PolicyResult.REJECTED;
                        log(ILogger.LL_FAILURE,
                                NAME + ": apply() - cert issuerDN mismatch: client issuerDN = " + oldIssuer
                                        + "; expected issuerDN = " + mIssuerDNString);
                    }
                }
            }
        } catch (Exception e) {
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR", params), "");
            result = PolicyResult.REJECTED;
        }

        if (result.equals(PolicyResult.ACCEPTED)) {
            log(ILogger.LL_INFO,
                    NAME + ": apply() - accepted");
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

        confParams.addElement(PROP_ISSUER_DN + "=" +
                mIssuerDNString);
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_ISSUER_DN + "=");
        return defParams;
    }

}
