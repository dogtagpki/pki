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
package org.dogtagpki.legacy.server.policy.constraints;

import java.util.Vector;

import org.dogtagpki.legacy.policy.EPolicyException;
import org.dogtagpki.legacy.policy.EnrollmentPolicy;
import org.dogtagpki.legacy.policy.PolicyProcessor;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

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
 * @version $Revision$ $Date$
 */
public class IssuerConstraints extends EnrollmentPolicy implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(IssuerConstraints.class);

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

    @Override
    public String[] getExtendedPluginInfo() {
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
    @Override
    public void init(PolicyProcessor owner, ConfigStore config) throws EPolicyException {
        try {
            mIssuerDNString = config.getString(PROP_ISSUER_DN, null);
            if ((mIssuerDNString != null) &&
                    !mIssuerDNString.equals("")) {
                mIssuerDN = new X500Name(mIssuerDNString);
            }
        } catch (Exception e) {
            logger.error(NAME + CMS.getLogMessage("CA_GET_ISSUER_NAME_FAILED"), e);

            String[] params = { getInstanceName(), e.toString() };
            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG", params), e);
        }
        logger.debug(NAME + ": init() done");
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    @Override
    public PolicyResult apply(Request req) {
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
                    logger.warn(CMS.getLogMessage("CA_GET_ISSUER_NAME_FAILED"));
                    logger.debug(NAME + ": apply() - issuerDN mismatch: client issuerDN = " + clientIssuerDN
                                    + "; expected issuerDN = " + mIssuerDNString);
                }
            } else {

                // Get the certificate info from the request
                X509CertInfo certInfo[] =
                        req.getExtDataInCertInfoArray(Request.CERT_INFO);

                if (certInfo == null) {
                    logger.warn(NAME + ": apply() - missing certInfo");
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
                        logger.warn(NAME + ": apply() - client issuerDN not found");
                    }
                    X500Name oi_name = new X500Name(oldIssuer);

                    if (!oi_name.equals(mIssuerDN)) {
                        setError(req,
                                CMS.getUserMessage("CMS_POLICY_INVALID_ISSUER",
                                        getInstanceName()), "");
                        result = PolicyResult.REJECTED;
                        logger.warn(NAME + ": apply() - cert issuerDN mismatch: client issuerDN = " + oldIssuer
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
            logger.info(NAME + ": apply() - accepted");
        }
        return result;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<>();

        confParams.addElement(PROP_ISSUER_DN + "=" +
                mIssuerDNString);
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<>();

        defParams.addElement(PROP_ISSUER_DN + "=");
        return defParams;
    }

}
