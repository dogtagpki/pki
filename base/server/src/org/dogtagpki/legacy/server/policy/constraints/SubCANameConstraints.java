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

import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.legacy.policy.IEnrollmentPolicy;
import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.legacy.server.policy.APolicyRule;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * This simple policy checks the subordinate CA CSR to see
 * if it is the same as the local CA.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class SubCANameConstraints extends APolicyRule implements IEnrollmentPolicy, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SubCANameConstraints.class);

    public ICertificateAuthority mCA = null;
    public String mIssuerNameStr = null;

    public SubCANameConstraints() {
        NAME = "SubCANameConstraints";
        DESC = "Enforces Subordinate CA name.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-subcanamecheck",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Checks if subordinate CA request matches the local CA. There are no parameters to change"
            };

        return params;

    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form ra.Policy.rule.<ruleName>.implName=KeyAlgorithmConstraints
     * ra.Policy.rule.<ruleName>.algorithms=RSA,DSA ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // get CA's public key to create authority key id.
        ICertAuthority certAuthority = (ICertAuthority)
                ((IPolicyProcessor) owner).getAuthority();

        if (certAuthority == null) {
            // should never get here.
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        "Cannot find the Certificate Manager"));
        }
        if (!(certAuthority instanceof ICertificateAuthority)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CANT_FIND_MANAGER"));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                        "Cannot find the Certificate Manager"));
        }
        mCA = (ICertificateAuthority) certAuthority;
        ISigningUnit su = mCA.getSigningUnit();
        CMSEngine engine = CMS.getCMSEngine();
        if (su == null || engine.isPreOpMode()) {
            logger.warn("SubCANameConstraints.init(): Abort due to missing signing unit or in pre-op mode");
            return;
        }

        X509CertImpl cert = su.getCertImpl();

        if (cert == null)
            return;
        X500Name issuerName = (X500Name) cert.getSubjectDN();

        if (issuerName == null)
            return;
        mIssuerNameStr = issuerName.toString();
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

            // Get the certificate templates
            X509CertInfo[] certInfos = req.getExtDataInCertInfoArray(
                    IRequest.CERT_INFO);

            if (certInfos == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_NO_CERT_INFO", getInstanceName()));
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO", NAME + ":" + getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // retrieve the subject name and check its unqiueness
            for (int i = 0; i < certInfos.length; i++) {
                CertificateSubjectName subName = (CertificateSubjectName) certInfos[i].get(X509CertInfo.SUBJECT);

                // if there is no name set, set one here.
                if (subName == null) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_NO_SUBJECT_NAME_1", getInstanceName()));
                    setError(req, CMS.getUserMessage("CMS_POLICY_NO_SUBJECT_NAME", NAME + ":" + getInstanceName()), "");
                    return PolicyResult.REJECTED;
                }
                String certSubjectName = subName.toString();

                if (certSubjectName.equalsIgnoreCase(mIssuerNameStr)) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_SUBJECT_NAME_EXIST_1", mIssuerNameStr));
                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_SUBJECT_NAME_EXIST", NAME + ":" + "Same As Issuer Name "
                                    + mIssuerNameStr), "");
                    result = PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_NO_SUBJECT_NAME_1", getInstanceName()));
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
        Vector<String> v = new Vector<String>();

        return v;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        return v;
    }
}
