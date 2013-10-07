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
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.PolicyConstraintsExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Policy Constraints Extension Policy
 * Adds the policy constraints extension to (CA) certificates.
 * Filtering of CA certificates is done through predicates.
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
public class PolicyConstraintsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_REQ_EXPLICIT_POLICY = "reqExplicitPolicy";
    protected static final String PROP_INHIBIT_POLICY_MAPPING = "inhibitPolicyMapping";

    protected static final boolean DEF_CRITICAL = false;
    protected static final int DEF_REQ_EXPLICIT_POLICY = -1; // not set
    protected static final int DEF_INHIBIT_POLICY_MAPPING = -1; // not set

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    protected boolean mCritical = DEF_CRITICAL;
    protected int mReqExplicitPolicy = DEF_REQ_EXPLICIT_POLICY;
    protected int mInhibitPolicyMapping = DEF_INHIBIT_POLICY_MAPPING;
    protected PolicyConstraintsExtension mPolicyConstraintsExtension = null;

    protected Vector<String> mInstanceParams = new Vector<String>();

    protected static Vector<String> mDefaultParams = new Vector<String>();
    static {
        mDefaultParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefaultParams.addElement(
                PROP_REQ_EXPLICIT_POLICY + "=" + DEF_REQ_EXPLICIT_POLICY);
        mDefaultParams.addElement(
                PROP_INHIBIT_POLICY_MAPPING + "=" + DEF_INHIBIT_POLICY_MAPPING);
    }

    public PolicyConstraintsExt() {
        NAME = "PolicyConstriantsExt";
        DESC = "Sets Policy Constraints Extension on subordinate CA certs";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.predicate=certType==ca ca.Policy.rule.<ruleName>.implName=
     * ca.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        // XXX should do do this ?
        // if CA does not allow subordinate CAs by way of basic constraints,
        // this policy always rejects
        /*****
         * ICertAuthority certAuthority = (ICertAuthority)
         * ((GenericPolicyProcessor)owner).mAuthority;
         * if (certAuthority instanceof ICertificateAuthority) {
         * CertificateChain caChain = certAuthority.getCACertChain();
         * X509Certificate caCert = null;
         * // Note that in RA the chain could be null if CA was not up when
         * // RA was started. In that case just set the length to -1 and let
         * // CA reject if it does not allow any subordinate CA certs.
         * if (caChain != null) {
         * caCert = caChain.getFirstCertificate();
         * if (caCert != null)
         * mCAPathLen = caCert.getBasicConstraints();
         * }
         * }
         ****/

        mEnabled = mConfig.getBoolean(
                    IPolicyProcessor.PROP_ENABLE, false);
        mCritical = mConfig.getBoolean(PROP_CRITICAL, DEF_CRITICAL);

        mReqExplicitPolicy = mConfig.getInteger(
                    PROP_REQ_EXPLICIT_POLICY, DEF_REQ_EXPLICIT_POLICY);
        mInhibitPolicyMapping = mConfig.getInteger(
                    PROP_INHIBIT_POLICY_MAPPING, DEF_INHIBIT_POLICY_MAPPING);

        if (mReqExplicitPolicy < -1)
            mReqExplicitPolicy = -1;
        if (mInhibitPolicyMapping < -1)
            mInhibitPolicyMapping = -1;

        // create instance of policy constraings extension
        try {
            mPolicyConstraintsExtension =
                    new PolicyConstraintsExtension(mCritical,
                            mReqExplicitPolicy, mInhibitPolicyMapping);
            CMS.debug(
                    "PolicyConstraintsExt: Created Policy Constraints Extension: " +
                            mPolicyConstraintsExtension);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_CANT_INIT_POLICY_CONST_EXT", e.toString()));
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Could not init Policy Constraints Extension. Error: " + e));
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                PROP_REQ_EXPLICIT_POLICY + "=" + mReqExplicitPolicy);
        mInstanceParams.addElement(
                PROP_INHIBIT_POLICY_MAPPING + "=" + mInhibitPolicyMapping);
    }

    /**
     * Adds Policy Constraints Extension to a (CA) certificate.
     *
     * If a Policy constraints Extension is already there, accept it if
     * it's been approved by agent, else replace it.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        // if extension hasn't been properly configured reject requests until
        // it has been resolved (or disabled).
        if (mPolicyConstraintsExtension == null) {
            return PolicyResult.ACCEPTED;
        }

        // get certInfo from request.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED;
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        // check if name constraints extension already exists.
        // if not agent approved, replace name constraints extension with ours.
        // else ignore.
        try {
            PolicyConstraintsExtension policyConstraintsExt = null;
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            try {
                if (extensions != null) {
                    policyConstraintsExt = (PolicyConstraintsExtension)
                            extensions.get(PolicyConstraintsExtension.NAME);
                }
            } catch (IOException e) {
                // extension isn't there.
            }

            if (policyConstraintsExt != null) {
                if (agentApproved(req)) {
                    return PolicyResult.ACCEPTED;
                } else {
                    extensions.delete(PolicyConstraintsExtension.NAME);
                }
            }

            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }
            extensions.set(
                    "PolicyConstriantsExt", mPolicyConstraintsExtension);
            CMS.debug("PolicyConstraintsExt: added our policy constraints extension");
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_CANT_PROCESS_POLICY_CONST_EXT", e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, e.getMessage());
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED;
        }
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        return mInstanceParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return mDefaultParams;
    }

    /**
     * gets plugin info for pretty console edit displays.
     */
    public String[] getExtendedPluginInfo(Locale locale) {
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                PROP_REQ_EXPLICIT_POLICY + "=" + mReqExplicitPolicy);
        mInstanceParams.addElement(
                PROP_INHIBIT_POLICY_MAPPING + "=" + mInhibitPolicyMapping);

        String[] params = {
                PROP_CRITICAL + ";boolean;RFC 2459 recommendation: may be critical or non-critical.",
                PROP_REQ_EXPLICIT_POLICY
                        + ";integer;Number of addional certificates that may appear in the path before an explicit policy is required. If less than 0 this field is unset in the extension.",
                PROP_INHIBIT_POLICY_MAPPING
                        + ";integer;Number of addional certificates that may appear in the path before policy mapping is no longer permitted. If less than 0 this field is unset in the extension.",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-policyrules-policyconstraints"
        };

        return params;
    }
}
