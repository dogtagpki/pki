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

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificatePolicyId;
import netscape.security.x509.CertificatePolicyMap;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.PolicyMappingsExtension;
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
 * Policy Mappings Extension Policy
 * Adds the Policy Mappings extension to a (CA) certificate.
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
public class PolicyMappingsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_NUM_POLICYMAPPINGS = "numPolicyMappings";

    protected static final String PROP_POLICYMAP = "policyMap";

    protected static final boolean DEF_CRITICAL = false;
    protected static final int DEF_NUM_POLICYMAPPINGS = 1;

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    protected boolean mCritical = DEF_CRITICAL;
    protected int mNumPolicyMappings = DEF_NUM_POLICYMAPPINGS;
    protected PolicyMap[] mPolicyMaps = null;
    protected PolicyMappingsExtension mPolicyMappingsExtension = null;

    protected Vector<String> mInstanceParams = new Vector<String>();

    public PolicyMappingsExt() {
        NAME = "PolicyMappingsExt";
        DESC = "Sets Policy Mappings Extension on subordinate CA certificates";
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
         * ((IPolicyProcessor)owner).getAuthority();
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

        mNumPolicyMappings = mConfig.getInteger(
                    PROP_NUM_POLICYMAPPINGS, DEF_NUM_POLICYMAPPINGS);
        if (mNumPolicyMappings < 1) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_ATTR_VALUE_2", NAME, ""));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_NUM_POLICYMAPPINGS,
                        "value must be greater than or equal to 1"));
        }

        // init Policy Mappings, check values if enabled.
        mPolicyMaps = new PolicyMap[mNumPolicyMappings];
        for (int i = 0; i < mNumPolicyMappings; i++) {
            String subtreeName = PROP_POLICYMAP + i;

            try {
                mPolicyMaps[i] = new PolicyMap(subtreeName, mConfig, mEnabled);
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, NAME + ": " +
                        CMS.getLogMessage("POLICY_ERROR_CREATE_MAP", e.toString()));
                throw e;
            }
        }

        // create instance of policy mappings extension if enabled.
        if (mEnabled) {
            try {
                Vector<CertificatePolicyMap> certPolicyMaps = new Vector<CertificatePolicyMap>();

                for (int j = 0; j < mNumPolicyMappings; j++) {
                    certPolicyMaps.addElement(
                            mPolicyMaps[j].mCertificatePolicyMap);
                }
                mPolicyMappingsExtension =
                        new PolicyMappingsExtension(mCritical, certPolicyMaps);
            } catch (IOException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                "Error initializing " + NAME + " Error: " + e));
            }
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                PROP_NUM_POLICYMAPPINGS + "=" + mNumPolicyMappings);
        for (int i = 0; i < mNumPolicyMappings; i++) {
            mPolicyMaps[i].getInstanceParams(mInstanceParams);
        }
    }

    /**
     * Adds policy mappings Extension to a (CA) certificate.
     *
     * If a policy mappings Extension is already there, accept it if
     * it's been approved by agent, else replace it.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        // if extension hasn't been properly configured reject requests until
        // it has been resolved (or disabled).
        if (mPolicyMappingsExtension == null) {
            //setError(req, PolicyResources.EXTENSION_NOT_INITED_1, NAME);
            //return PolicyResult.REJECTED;
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
        // check if policy mappings extension already exists.
        // if not agent approved, replace policy mappings extension with ours.
        // else ignore.
        try {
            PolicyMappingsExtension policyMappingsExt = null;
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            try {
                if (extensions != null) {
                    policyMappingsExt = (PolicyMappingsExtension)
                            extensions.get(PolicyMappingsExtension.NAME);
                }
            } catch (IOException e) {
                // extension isn't there.
            }

            if (policyMappingsExt != null) {
                if (agentApproved(req)) {
                    return PolicyResult.ACCEPTED;
                } else {
                    extensions.delete(PolicyMappingsExtension.NAME);
                }
            }

            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }
            extensions.set(
                    PolicyMappingsExtension.NAME, mPolicyMappingsExtension);
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_PROCESS_POLICYMAP_EXT", e.getMessage()));
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
     * Default config parameters.
     * To add more permitted or excluded subtrees,
     * increase the num to greater than 0 and more configuration params
     * will show up in the console.
     */
    private static Vector<String> mDefParams = new Vector<String>();
    static {
        mDefParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefParams.addElement(
                PROP_NUM_POLICYMAPPINGS + "=" + DEF_NUM_POLICYMAPPINGS);
        String policyMap0Dot = PROP_POLICYMAP + "0.";

        mDefParams.addElement(
                policyMap0Dot + PolicyMap.PROP_ISSUER_DOMAIN_POLICY + "=" + "");
        mDefParams.addElement(
                policyMap0Dot + PolicyMap.PROP_SUBJECT_DOMAIN_POLICY + "=" + "");
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return mDefParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> theparams = new Vector<String>();

        theparams.addElement(PROP_CRITICAL + ";boolean;RFC 2459 recommendation: MUST be non-critical.");
        theparams.addElement(PROP_NUM_POLICYMAPPINGS
                + ";number; Number of policy mappings. The value must be greater than or equal to 1");

        String policyInfo =
                ";string;An object identifier in the form n.n.n.n";

        for (int k = 0; k < 5; k++) {
            String policyMapkDot = PROP_POLICYMAP + k + ".";

            theparams.addElement(policyMapkDot +
                    PolicyMap.PROP_ISSUER_DOMAIN_POLICY + policyInfo);
            theparams.addElement(policyMapkDot +
                    PolicyMap.PROP_SUBJECT_DOMAIN_POLICY + policyInfo);
        }

        theparams.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-policymappings");
        theparams.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Policy Mappings Extension. See RFC 2459 (4.2.1.6)");

        String[] params = new String[theparams.size()];

        theparams.copyInto(params);
        return params;
    }
}

class PolicyMap {

    protected static String PROP_ISSUER_DOMAIN_POLICY = "issuerDomainPolicy";
    protected static String PROP_SUBJECT_DOMAIN_POLICY = "subjectDomainPolicy";

    protected String mName = null;
    protected String mNameDot = null;
    protected IConfigStore mConfig = null;
    protected String mIssuerDomainPolicy = null;
    protected String mSubjectDomainPolicy = null;
    protected CertificatePolicyMap mCertificatePolicyMap = null;

    /**
     * forms policy map parameters.
     *
     * @param name name of this policy map, for example policyMap0
     * @param config parent's config from where we find this configuration.
     * @param enabled whether policy was enabled.
     */
    protected PolicyMap(String name, IConfigStore config, boolean enabled)
            throws EBaseException {
        mName = name;
        mConfig = config.getSubStore(mName);
        mNameDot = mName + ".";

        if (mConfig == null) {
            CMS.debug("PolicyMappingsExt::PolicyMap - mConfig is null!");
            return;
        }

        // if there's no configuration for this map put it there.
        if (mConfig.size() == 0) {
            config.putString(mNameDot + PROP_ISSUER_DOMAIN_POLICY, "");
            config.putString(mNameDot + PROP_SUBJECT_DOMAIN_POLICY, "");
            mConfig = config.getSubStore(mName);
            if (mConfig == null || mConfig.size() == 0) {
                CMS.debug("PolicyMappingsExt::PolicyMap - mConfig " +
                           "is null or empty!");
                return;
            }
        }

        // get policy ids from configuration.
        mIssuerDomainPolicy =
                mConfig.getString(PROP_ISSUER_DOMAIN_POLICY, null);
        mSubjectDomainPolicy =
                mConfig.getString(PROP_SUBJECT_DOMAIN_POLICY, null);

        // adjust for "" and console returning "null"
        if (mIssuerDomainPolicy != null &&
                (mIssuerDomainPolicy.length() == 0 ||
                mIssuerDomainPolicy.equals("null"))) {
            mIssuerDomainPolicy = null;
        }
        if (mSubjectDomainPolicy != null &&
                (mSubjectDomainPolicy.length() == 0 ||
                mSubjectDomainPolicy.equals("null"))) {
            mSubjectDomainPolicy = null;
        }

        // policy ids cannot be null if policy is enabled.
        String msg = "value cannot be null.";

        if (mIssuerDomainPolicy == null && enabled)
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mNameDot + PROP_ISSUER_DOMAIN_POLICY, msg));
        if (mSubjectDomainPolicy == null && enabled)
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mNameDot + PROP_SUBJECT_DOMAIN_POLICY, msg));

        // if a policy id is not null check that it is a valid OID.
        ObjectIdentifier issuerPolicyId = null;
        ObjectIdentifier subjectPolicyId = null;

        if (mIssuerDomainPolicy != null)
            issuerPolicyId = CMS.checkOID(
                        mNameDot + PROP_ISSUER_DOMAIN_POLICY, mIssuerDomainPolicy);
        if (mSubjectDomainPolicy != null)
            subjectPolicyId = CMS.checkOID(
                        mNameDot + PROP_SUBJECT_DOMAIN_POLICY, mSubjectDomainPolicy);

        // if enabled, form CertificatePolicyMap to be encoded in extension.
        // policy ids should be all set.
        if (enabled) {
            mCertificatePolicyMap = new CertificatePolicyMap(
                        new CertificatePolicyId(issuerPolicyId),
                        new CertificatePolicyId(subjectPolicyId));
        }
    }

    protected void getInstanceParams(Vector<String> instanceParams) {
        instanceParams.addElement(
                mNameDot + PROP_ISSUER_DOMAIN_POLICY + "=" + (mIssuerDomainPolicy == null ? "" :
                        mIssuerDomainPolicy));
        instanceParams.addElement(
                mNameDot + PROP_SUBJECT_DOMAIN_POLICY + "=" + (mSubjectDomainPolicy == null ? "" :
                        mSubjectDomainPolicy));
    }

}
