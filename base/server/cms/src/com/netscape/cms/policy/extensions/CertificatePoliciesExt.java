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
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CPSuri;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificatePoliciesExtension;
import netscape.security.x509.CertificatePolicyId;
import netscape.security.x509.CertificatePolicyInfo;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.DisplayText;
import netscape.security.x509.NoticeReference;
import netscape.security.x509.PolicyQualifierInfo;
import netscape.security.x509.PolicyQualifiers;
import netscape.security.x509.UserNotice;
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
 * Certificate Policies.
 * Adds certificate policies extension.
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
public class CertificatePoliciesExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_NUM_CERTPOLICIES = "numCertPolicies";

    protected static final String PROP_CERTPOLICY = "certPolicy";

    protected static final boolean DEF_CRITICAL = false;
    protected static final int DEF_NUM_CERTPOLICIES = 1;

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    protected boolean mCritical = DEF_CRITICAL;
    protected int mNumCertPolicies = DEF_NUM_CERTPOLICIES;
    protected CertPolicy[] mCertPolicies = null;

    protected Vector<String> mInstanceParams = new Vector<String>();
    protected CertificatePoliciesExtension mCertificatePoliciesExtension = null;

    public CertificatePoliciesExt() {
        NAME = "CertificatePoliciesExt";
        DESC = "Sets non-critical certificate policies extension in certs";
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

        mEnabled = mConfig.getBoolean(
                    IPolicyProcessor.PROP_ENABLE, false);
        mCritical = mConfig.getBoolean(PROP_CRITICAL, DEF_CRITICAL);

        mNumCertPolicies = mConfig.getInteger(
                    PROP_NUM_CERTPOLICIES, DEF_NUM_CERTPOLICIES);
        if (mNumCertPolicies < 1) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_ATTR_VALUE_2", NAME, ""));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_NUM_CERTPOLICIES,
                        "value must be greater than or equal to 1"));
        }

        // init Policy Mappings, check values if enabled.
        mCertPolicies = new CertPolicy[mNumCertPolicies];
        for (int i = 0; i < mNumCertPolicies; i++) {
            String subtreeName = PROP_CERTPOLICY + i;

            try {
                mCertPolicies[i] = new CertPolicy(subtreeName, mConfig, mEnabled);
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, NAME + ": " +
                        CMS.getLogMessage("POLICY_ERROR_CREATE_CERT_POLICY", e.toString()));
                throw e;
            }
        }

        // create instance of certificate policy extension if enabled.
        if (mEnabled) {
            try {
                Vector<CertificatePolicyInfo> CertPolicies = new Vector<CertificatePolicyInfo>();

                for (int j = 0; j < mNumCertPolicies; j++) {
                    CertPolicies.addElement(
                            mCertPolicies[j].mCertificatePolicyInfo);
                }
                mCertificatePoliciesExtension =
                        new CertificatePoliciesExtension(mCritical, CertPolicies);
            } catch (IOException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                "Error initializing " + NAME + " Error: " + e));
            }
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                PROP_NUM_CERTPOLICIES + "=" + mNumCertPolicies);
        for (int i = 0; i < mNumCertPolicies; i++) {
            mCertPolicies[i].getInstanceParams(mInstanceParams);
        }
    }

    /**
     * Applies the policy on the given Request.
     * <p>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

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
        CertificateExtensions extensions = null;

        try {
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
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
                    extensions.delete(CertificatePoliciesExtension.NAME);
                } catch (IOException e) {
                    // this is the hack: for some reason, the key which is the name
                    // of the policy has been converted into the OID
                    try {
                        extensions.delete("2.5.29.32");
                    } catch (IOException ee) {
                    }
                }
            }
            extensions.set(CertificatePoliciesExtension.NAME,
                    mCertificatePoliciesExtension);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_ERROR_CERTIFICATE_POLICIES_1",
                    e.toString()));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR"), NAME);
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_ERROR_CERTIFICATE_POLICIES_1",
                    e.toString()));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR"), NAME);
            return PolicyResult.REJECTED;
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_ERROR_CERTIFICATE_POLICIES_1",
                    e.toString()));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR"), NAME);
            return PolicyResult.REJECTED;
        }
        return PolicyResult.ACCEPTED;
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
                PROP_NUM_CERTPOLICIES + "=" + DEF_NUM_CERTPOLICIES);
        String certPolicy0Dot = PROP_CERTPOLICY + "0.";

        mDefParams.addElement(
                certPolicy0Dot + CertPolicy.PROP_POLICY_IDENTIFIER + "=" + "");
        mDefParams.addElement(
                certPolicy0Dot + CertPolicy.PROP_NOTICE_REF_ORG + "=" + "");
        mDefParams.addElement(
                certPolicy0Dot + CertPolicy.PROP_NOTICE_REF_NUMS + "=" + "");
        mDefParams.addElement(
                certPolicy0Dot + CertPolicy.PROP_USER_NOTICE_TEXT + "=" + "");
        mDefParams.addElement(
                certPolicy0Dot + CertPolicy.PROP_CPS_URI + "=" + "");

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

        theparams.addElement(PROP_CRITICAL + ";boolean;RFC 3280 recommendation: MUST be non-critical.");
        theparams.addElement(PROP_NUM_CERTPOLICIES
                + ";number; Number of certificate policies. The value must be greater than or equal to 1");

        for (int k = 0; k < 5; k++) {
            String certPolicykDot = PROP_CERTPOLICY + k + ".";

            theparams.addElement(certPolicykDot +
                    CertPolicy.PROP_POLICY_IDENTIFIER + ";string,required;An object identifier in the form n.n.n.n");
            theparams.addElement(certPolicykDot +
                    CertPolicy.PROP_NOTICE_REF_ORG + ";string;See RFC 3280 sec 4.2.1.5");
            theparams.addElement(certPolicykDot +
                    CertPolicy.PROP_NOTICE_REF_NUMS +
                    ";string;comma-separated list of numbers. See RFC 3280 sec 4.2.1.5");
            theparams.addElement(certPolicykDot +
                    CertPolicy.PROP_USER_NOTICE_TEXT + ";string;See RFC 3280 sec 4.2.1.5");
            theparams.addElement(certPolicykDot +
                    CertPolicy.PROP_CPS_URI + ";string;See RFC 3280 sec 4.2.1.5");
        }

        theparams.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-certificatepolicies");
        theparams.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Certificate Policies Extension. See RFC 3280 (4.2.1.5)");

        String[] params = new String[theparams.size()];

        theparams.copyInto(params);
        return params;
    }
}

class CertPolicy {

    protected static final String PROP_POLICY_IDENTIFIER = "policyId";
    protected static final String PROP_NOTICE_REF_ORG = "noticeRefOrganization";
    protected static final String PROP_NOTICE_REF_NUMS = "noticeRefNumbers";
    protected static final String PROP_USER_NOTICE_TEXT = "userNoticeExplicitText";
    protected static final String PROP_CPS_URI = "cpsURI";

    protected String mName = null;
    protected String mNameDot = null;
    protected IConfigStore mConfig = null;

    protected String mPolicyId = null;
    protected String mNoticeRefOrg = null;
    protected String mNoticeRefNums = null;
    protected String mNoticeRefExplicitText = null;
    protected String mCpsUri = null;

    protected CertificatePolicyInfo mCertificatePolicyInfo = null;

    /**
     * forms policy map parameters.
     *
     * @param name name of this policy map, for example certPolicy0
     * @param config parent's config from where we find this configuration.
     * @param enabled whether policy was enabled.
     */
    protected CertPolicy(String name, IConfigStore config, boolean enabled)
            throws EBaseException {
        mName = name;
        mConfig = config.getSubStore(mName);
        mNameDot = mName + ".";

        if (mConfig == null) {
            CMS.debug("CertificatePoliciesExt::CertPolicy - mConfig is " +
                       "null!");
            throw new EBaseException("mConfig is null");
        }

        // if there's no configuration for this policy put it there.
        if (mConfig.size() == 0) {
            config.putString(mNameDot + PROP_POLICY_IDENTIFIER, "");
            config.putString(mNameDot + PROP_NOTICE_REF_ORG, "");
            config.putString(mNameDot + PROP_NOTICE_REF_NUMS, "");
            config.putString(mNameDot + PROP_USER_NOTICE_TEXT, "");
            config.putString(mNameDot + PROP_CPS_URI, "");
            mConfig = config.getSubStore(mName);
            if (mConfig == null || mConfig.size() == 0) {
                CMS.debug("CertificatePoliciesExt::CertPolicy - mConfig " +
                           "is null or empty!");
                throw new EBaseException("mConfig is null or empty");
            }
        }

        // get policy ids from configuration.
        mPolicyId = mConfig.getString(PROP_POLICY_IDENTIFIER, null);
        mNoticeRefOrg = mConfig.getString(PROP_NOTICE_REF_ORG, null);
        mNoticeRefNums = mConfig.getString(PROP_NOTICE_REF_NUMS, null);
        mNoticeRefExplicitText = mConfig.getString(PROP_USER_NOTICE_TEXT, null);
        mCpsUri = mConfig.getString(PROP_CPS_URI, null);

        // adjust for "" and console returning "null"
        if (mPolicyId != null &&
                (mPolicyId.length() == 0 ||
                mPolicyId.equals("null"))) {
            mPolicyId = null;
        }
        if (mNoticeRefOrg != null &&
                (mNoticeRefOrg.length() == 0 ||
                mNoticeRefOrg.equals("null"))) {
            mNoticeRefOrg = null;
        }
        if (mNoticeRefNums != null &&
                (mNoticeRefNums.length() == 0 ||
                mNoticeRefNums.equals("null"))) {
            mNoticeRefNums = null;
        }
        if (mNoticeRefExplicitText != null &&
                (mNoticeRefExplicitText.length() == 0 ||
                mNoticeRefExplicitText.equals("null"))) {
            mNoticeRefExplicitText = null;
        }
        if (mCpsUri != null &&
                (mCpsUri.length() == 0 ||
                mCpsUri.equals("null"))) {
            mCpsUri = null;
        }

        // policy ids cannot be null if policy is enabled.
        String msg = "value cannot be null.";

        if (mPolicyId == null && enabled)
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mNameDot + PROP_POLICY_IDENTIFIER, msg));
        msg = "NoticeReference is optional; If chosen to include, NoticeReference must at least has 'organization'";
        if (mNoticeRefOrg == null && mNoticeRefNums != null && enabled)
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        mNameDot + PROP_NOTICE_REF_ORG, msg));

        // if a policy id is not null check that it is a valid OID.

        if (mPolicyId != null)
            CMS.checkOID(mNameDot + PROP_POLICY_IDENTIFIER, mPolicyId);

        // if enabled, form CertificatePolicyInfo to be encoded in
        // extension. Policy ids should be all set.
        if (enabled) {
            CMS.debug("CertPolicy: in CertPolicy");
            DisplayText displayText = null;

            if (mNoticeRefExplicitText != null &&
                    !mNoticeRefExplicitText.equals(""))
                displayText = new DisplayText(DisplayText.tag_VisibleString, mNoticeRefExplicitText);
            //		  new DisplayText(DisplayText.tag_IA5String, mNoticeRefExplicitText);
            DisplayText orgName = null;

            if (mNoticeRefOrg != null &&
                    !mNoticeRefOrg.equals(""))
                orgName =
                        new DisplayText(DisplayText.tag_VisibleString, mNoticeRefOrg);
            //		  new DisplayText(DisplayText.tag_VisibleString, mNoticeRefOrg);

            int[] nums = new int[0];
            ;
            if (mNoticeRefNums != null &&
                    !mNoticeRefNums.equals("")) {

                // should add a method to NoticeReference to take a
                // Vector...but let's do this for now

                Vector<String> numsVector = new Vector<String>();
                StringTokenizer tokens = new StringTokenizer(mNoticeRefNums,
                        ",");

                while (tokens.hasMoreTokens()) {
                    String num = tokens.nextToken().trim();

                    numsVector.addElement(num);
                }

                nums = new int[numsVector.size()];

                for (int i = 0; i < numsVector.size(); i++) {
                    Integer ii = new Integer(numsVector.elementAt(i));

                    nums[i] = ii.intValue();
                }
            }
            CertificatePolicyId cpolicyId = null;

            try {
                cpolicyId = new CertificatePolicyId(ObjectIdentifier.getObjectIdentifier(mPolicyId));
            } catch (Exception e) {
                throw new EBaseException(CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR", mPolicyId));
            }

            PolicyQualifiers policyQualifiers = new PolicyQualifiers();

            NoticeReference noticeReference = null;

            if (orgName != null)
                noticeReference = new NoticeReference(orgName, nums);

            UserNotice userNotice = null;

            if (displayText != null || noticeReference != null) {
                userNotice = new UserNotice(noticeReference, displayText);

                PolicyQualifierInfo policyQualifierInfo1 =
                        new PolicyQualifierInfo(PolicyQualifierInfo.QT_UNOTICE, userNotice);

                policyQualifiers.add(policyQualifierInfo1);
            }

            CPSuri cpsUri = null;

            if (mCpsUri != null && mCpsUri.length() > 0) {
                cpsUri = new CPSuri(mCpsUri);
                PolicyQualifierInfo policyQualifierInfo2 =
                        new PolicyQualifierInfo(PolicyQualifierInfo.QT_CPS, cpsUri);

                policyQualifiers.add(policyQualifierInfo2);
            }

            if ((mNoticeRefOrg == null || mNoticeRefOrg.equals("")) &&
                    (mNoticeRefExplicitText == null || mNoticeRefExplicitText.equals("")) &&
                    (mCpsUri == null || mCpsUri.equals(""))) {
                CMS.debug("CertPolicy mNoticeRefOrg = " + mNoticeRefOrg);
                CMS.debug("CertPolicy mNoticeRefExplicitText = " + mNoticeRefExplicitText);
                CMS.debug("CertPolicy mCpsUri = " + mCpsUri);

                mCertificatePolicyInfo = new CertificatePolicyInfo(cpolicyId);
            } else {
                CMS.debug("CertPolicy mNoticeRefOrg = " + mNoticeRefOrg);
                CMS.debug("CertPolicy mNoticeRefExplicitText = " + mNoticeRefExplicitText);
                CMS.debug("CertPolicy mCpsUri = " + mCpsUri);
                mCertificatePolicyInfo = new CertificatePolicyInfo(cpolicyId, policyQualifiers);
            }
        }
    }

    protected void getInstanceParams(Vector<String> instanceParams) {
        instanceParams.addElement(
                mNameDot + PROP_POLICY_IDENTIFIER + "=" + (mPolicyId == null ? "" :
                        mPolicyId));
        instanceParams.addElement(
                mNameDot + PROP_NOTICE_REF_ORG + "=" + (mNoticeRefOrg == null ? "" :
                        mNoticeRefOrg));
        instanceParams.addElement(
                mNameDot + PROP_NOTICE_REF_NUMS + "=" + (mNoticeRefNums == null ? "" :
                        mNoticeRefNums));
        instanceParams.addElement(
                mNameDot + PROP_USER_NOTICE_TEXT + "=" + (mNoticeRefExplicitText == null ? "" :
                        mNoticeRefExplicitText));
        instanceParams.addElement(
                mNameDot + PROP_CPS_URI + "=" + (mCpsUri == null ? "" :
                        mCpsUri));
    }
}
