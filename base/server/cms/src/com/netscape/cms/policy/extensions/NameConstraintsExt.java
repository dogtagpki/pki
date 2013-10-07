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
import netscape.security.x509.GeneralSubtree;
import netscape.security.x509.GeneralSubtrees;
import netscape.security.x509.NameConstraintsExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IGeneralNameAsConstraintsConfig;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Name Constraints Extension Policy
 * Adds the name constraints extension to a (CA) certificate.
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
public class NameConstraintsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_NUM_PERMITTEDSUBTREES = "numPermittedSubtrees";
    protected static final String PROP_NUM_EXCLUDEDSUBTREES = "numExcludedSubtrees";

    protected static final String PROP_PERMITTEDSUBTREES = "permittedSubtrees";
    protected static final String PROP_EXCLUDEDSUBTREES = "excludedSubtrees";

    protected static final boolean DEF_CRITICAL = true;
    protected static final int DEF_NUM_PERMITTEDSUBTREES = 8;
    protected static final int DEF_NUM_EXCLUDEDSUBTREES = 8;

    protected boolean mEnabled = false;
    protected IConfigStore mConfig = null;

    protected boolean mCritical = DEF_CRITICAL;
    protected int mNumPermittedSubtrees = 0;
    protected int mNumExcludedSubtrees = 0;
    protected Subtree[] mPermittedSubtrees = null;
    protected Subtree[] mExcludedSubtrees = null;
    protected NameConstraintsExtension mNameConstraintsExtension = null;

    protected Vector<String> mInstanceParams = new Vector<String>();

    public NameConstraintsExt() {
        NAME = "NameConstraintsExt";
        DESC = "Sets Name Constraints Extension on subordinate CA certificates";
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
        mNumPermittedSubtrees = mConfig.getInteger(
                    PROP_NUM_PERMITTEDSUBTREES, DEF_NUM_PERMITTEDSUBTREES);
        mNumExcludedSubtrees = mConfig.getInteger(
                    PROP_NUM_EXCLUDEDSUBTREES, DEF_NUM_EXCLUDEDSUBTREES);

        if (mNumPermittedSubtrees < 0) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_NUM_PERMITTEDSUBTREES,
                        "value must be greater than or equal to 0"));
        }
        if (mNumExcludedSubtrees < 0) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_NUM_EXCLUDEDSUBTREES,
                        "value must be greater than or equal to 0"));
        }

        // init permitted subtrees if any.
        if (mNumPermittedSubtrees > 0) {
            mPermittedSubtrees =
                    form_subtrees(PROP_PERMITTEDSUBTREES, mNumPermittedSubtrees);
            CMS.debug("NameConstraintsExt: formed permitted subtrees");
        }

        // init excluded subtrees if any.
        if (mNumExcludedSubtrees > 0) {
            mExcludedSubtrees =
                    form_subtrees(PROP_EXCLUDEDSUBTREES, mNumExcludedSubtrees);
            CMS.debug("NameConstraintsExt: formed excluded subtrees");
        }

        // create instance of name constraints extension if enabled.
        if (mEnabled) {
            try {
                Vector<GeneralSubtree> permittedSubtrees = new Vector<GeneralSubtree>();

                for (int i = 0; i < mNumPermittedSubtrees; i++) {
                    permittedSubtrees.addElement(
                            mPermittedSubtrees[i].mGeneralSubtree);
                }
                Vector<GeneralSubtree> excludedSubtrees = new Vector<GeneralSubtree>();

                for (int j = 0; j < mNumExcludedSubtrees; j++) {
                    excludedSubtrees.addElement(
                            mExcludedSubtrees[j].mGeneralSubtree);
                }
                GeneralSubtrees psb = null;

                if (permittedSubtrees.size() > 0) {
                    psb = new GeneralSubtrees(permittedSubtrees);
                }
                GeneralSubtrees esb = null;

                if (excludedSubtrees.size() > 0) {
                    esb = new GeneralSubtrees(excludedSubtrees);
                }
                mNameConstraintsExtension =
                        new NameConstraintsExtension(mCritical,
                                psb,
                                esb);
                CMS.debug("NameConstraintsExt: formed Name Constraints Extension " +
                        mNameConstraintsExtension);
            } catch (IOException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                "Error initializing Name Constraints Extension: " + e));
            }
        }

        // form instance params
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                PROP_NUM_PERMITTEDSUBTREES + "=" + mNumPermittedSubtrees);
        mInstanceParams.addElement(
                PROP_NUM_EXCLUDEDSUBTREES + "=" + mNumExcludedSubtrees);
        if (mNumPermittedSubtrees > 0) {
            for (int i = 0; i < mPermittedSubtrees.length; i++)
                mPermittedSubtrees[i].getInstanceParams(mInstanceParams);
        }
        if (mNumExcludedSubtrees > 0) {
            for (int j = 0; j < mExcludedSubtrees.length; j++)
                mExcludedSubtrees[j].getInstanceParams(mInstanceParams);
        }
    }

    Subtree[] form_subtrees(String subtreesName, int numSubtrees)
            throws EBaseException {
        Subtree[] subtrees = new Subtree[numSubtrees];

        for (int i = 0; i < numSubtrees; i++) {
            String subtreeName = subtreesName + i;
            IConfigStore subtreeConfig = mConfig.getSubStore(subtreeName);
            Subtree subtree =
                    new Subtree(subtreeName, subtreeConfig, mEnabled);

            subtrees[i] = subtree;
        }
        return subtrees;
    }

    /**
     * Adds Name Constraints Extension to a (CA) certificate.
     *
     * If a Name constraints Extension is already there, accept it if
     * it's been approved by agent, else replace it.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        // if extension hasn't been properly configured reject requests until
        // it has been resolved (or disabled).
        if (mNameConstraintsExtension == null) {
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
        // check if name constraints extension already exists.
        // if not agent approved, replace name constraints extension with ours.
        // else ignore.
        try {
            NameConstraintsExtension nameConstraintsExt = null;
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            try {
                if (extensions != null) {
                    nameConstraintsExt = (NameConstraintsExtension)
                            extensions.get(NameConstraintsExtension.NAME);
                }
            } catch (IOException e) {
                // extension isn't there.
            }

            if (nameConstraintsExt != null) {
                if (agentApproved(req)) {
                    CMS.debug(
                            "NameConstraintsExt: request id from agent " + req.getRequestId() +
                                    " already has name constraints - accepted");
                    return PolicyResult.ACCEPTED;
                } else {
                    CMS.debug(
                            "NameConstraintsExt: request id " + req.getRequestId() + " from user " +
                                    " already has name constraints - deleted");
                    extensions.delete(NameConstraintsExtension.NAME);
                }
            }

            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }
            extensions.set(
                    NameConstraintsExtension.NAME, mNameConstraintsExtension);
            CMS.debug(
                    "NameConstraintsExt: added Name Constraints Extension to request " +
                            req.getRequestId());
            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_NAME_CONST_EXTENSION", e.getMessage()));
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
                PROP_NUM_PERMITTEDSUBTREES + "=" + DEF_NUM_PERMITTEDSUBTREES);
        mDefParams.addElement(
                PROP_NUM_EXCLUDEDSUBTREES + "=" + DEF_NUM_EXCLUDEDSUBTREES);
        for (int k = 0; k < DEF_NUM_PERMITTEDSUBTREES; k++) {
            Subtree.getDefaultParams(PROP_PERMITTEDSUBTREES + k, mDefParams);
        }
        for (int l = 0; l < DEF_NUM_EXCLUDEDSUBTREES; l++) {
            Subtree.getDefaultParams(PROP_EXCLUDEDSUBTREES + l, mDefParams);
        }
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

        theparams.addElement(PROP_CRITICAL + ";boolean;RFC 2459 recommendation: MUST be critical.");
        theparams.addElement(
                PROP_NUM_PERMITTEDSUBTREES + ";number;See RFC 2459 sec 4.2.1.11");
        theparams.addElement(
                PROP_NUM_EXCLUDEDSUBTREES + ";number;See RFC 2459 sec 4.2.1.11");

        // now do the subtrees.
        for (int k = 0; k < DEF_NUM_PERMITTEDSUBTREES; k++) {
            Subtree.getExtendedPluginInfo(PROP_PERMITTEDSUBTREES + k, theparams);
        }
        for (int l = 0; l < DEF_NUM_EXCLUDEDSUBTREES; l++) {
            Subtree.getExtendedPluginInfo(PROP_EXCLUDEDSUBTREES + l, theparams);
        }
        theparams.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-nameconstraints");
        theparams.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Name Constraints Extension. See RFC 2459");

        String[] info = new String[theparams.size()];

        theparams.copyInto(info);
        return info;
    }
}

/**
 * subtree configuration
 */
class Subtree {

    protected static final String PROP_BASE = "base";
    protected static final String PROP_MIN = "min";
    protected static final String PROP_MAX = "max";

    protected static final int DEF_MIN = 0;
    protected static final int DEF_MAX = -1; // -1 (less than 0) means not set.

    protected static final String MINMAX_INFO = "number;See RFC 2459 section 4.2.1.11";

    String mName = null;
    IConfigStore mConfig = null;
    int mMin = DEF_MIN, mMax = DEF_MAX;
    IGeneralNameAsConstraintsConfig mBase = null;
    GeneralSubtree mGeneralSubtree = null;

    String mNameDot = null;
    String mNameDotMin = null;
    String mNameDotMax = null;

    public Subtree(
            String subtreeName, IConfigStore config, boolean policyEnabled)
            throws EBaseException {
        mName = subtreeName;
        mConfig = config;

        if (mName != null) {
            mNameDot = mName + ".";
            mNameDotMin = mNameDot + PROP_MIN;
            mNameDotMax = mNameDot + PROP_MAX;
        } else {
            mNameDot = "";
            mNameDotMin = PROP_MIN;
            mNameDotMax = PROP_MAX;
        }

        // necessary to expand/shrink # general names from console.
        if (mConfig.size() == 0) {
            mConfig.putInteger(mNameDotMin, mMin);
            mConfig.putInteger(mNameDotMax, mMax);
            // GeneralNameConfig will take care of stuff for generalname.
        }

        // if policy enabled get values to form the general subtree.
        mMin = mConfig.getInteger(PROP_MIN, DEF_MIN);
        mMax = mConfig.getInteger(PROP_MAX, DEF_MAX);
        if (mMax < -1)
            mMax = -1;
        mBase = CMS.createGeneralNameAsConstraintsConfig(
                    mNameDot + PROP_BASE, mConfig.getSubStore(PROP_BASE),
                    true, policyEnabled);

        if (policyEnabled) {
            mGeneralSubtree =
                    new GeneralSubtree(mBase.getGeneralName(), mMin, mMax);
        }
    }

    void getInstanceParams(Vector<String> instanceParams) {
        mBase.getInstanceParams(instanceParams);
        instanceParams.addElement(mNameDotMin + "=" + mMin);
        instanceParams.addElement(mNameDotMax + "=" + mMax);
    }

    static void getDefaultParams(String name, Vector<String> params) {
        String nameDot = "";

        if (name != null && name.length() >= 0)
            nameDot = name + ".";
        CMS.getGeneralNameConfigDefaultParams(nameDot + PROP_BASE, true, params);
        params.addElement(nameDot + PROP_MIN + "=" + DEF_MIN);
        params.addElement(nameDot + PROP_MAX + "=" + DEF_MAX);
    }

    static void getExtendedPluginInfo(String name, Vector<String> info) {
        String nameDot = "";

        if (name != null && name.length() > 0)
            nameDot = name + ".";
        CMS.getGeneralNameConfigExtendedPluginInfo(nameDot + PROP_BASE, true, info);
        info.addElement(nameDot + PROP_MIN + ";" + MINMAX_INFO);
        info.addElement(nameDot + PROP_MAX + ";" + MINMAX_INFO);
    }
}
