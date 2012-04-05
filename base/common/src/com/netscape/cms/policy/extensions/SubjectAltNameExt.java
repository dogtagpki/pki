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
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IGeneralNameUtil;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.policy.ISubjAltNameConfig;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Subject Alternative Name extension policy.
 *
 * Adds the subject alternative name extension as configured.
 *
 * Two forms are supported. 1) For S/MIME certificates, email
 * addresses are copied from data stored in the request by the
 * authentication component. Both 'e' and 'altEmail' are supported
 * so that both the primary address and alternative forms may be
 * certified. Only the primary goes in the subjectName position (which
 * should be phased out).
 *
 * e
 * mailAlternateAddress
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
public class SubjectAltNameExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    // (standard says SHOULD be marked critical if included.)
    protected static final String PROP_CRITICAL = "critical";
    protected static final boolean DEF_CRITICAL = false;

    protected IConfigStore mConfig = null;
    protected boolean mEnabled = false;
    protected boolean mCritical = DEF_CRITICAL;
    protected int mNumGNs = 0;
    protected ISubjAltNameConfig[] mGNs = null;

    Vector<String> mInstanceParams = new Vector<String>();

    // init default params and extended plugin info.
    private static Vector<String> mDefParams = new Vector<String>();
    static {
        // default params.
        mDefParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefParams.addElement(
                IGeneralNameUtil.PROP_NUM_GENERALNAMES + "=" +
                        IGeneralNameUtil.DEF_NUM_GENERALNAMES);
        for (int i = 0; i < IGeneralNameUtil.DEF_NUM_GENERALNAMES; i++) {
            CMS.getSubjAltNameConfigDefaultParams(
                    IGeneralNameUtil.PROP_GENERALNAME + i, mDefParams);
        }
    }

    private String[] mExtendedPluginInfo = null;

    public SubjectAltNameExt() {
        NAME = "SubjectAltNameExt";
        DESC = "Sets alternative subject names for certificates";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=SubjectAltNameExt ra.Policy.rule.<ruleName>.enable=true
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        // get criticality
        mCritical = mConfig.getBoolean(PROP_CRITICAL, DEF_CRITICAL);

        // get enabled
        mEnabled = mConfig.getBoolean(
                    IPolicyProcessor.PROP_ENABLE, false);

        // get general names configuration.
        mNumGNs = mConfig.getInteger(IGeneralNameUtil.PROP_NUM_GENERALNAMES);
        if (mNumGNs <= 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_MUST_BE_POSITIVE_NUMBER",
                            IGeneralNameUtil.PROP_NUM_GENERALNAMES));
        }
        mGNs = new ISubjAltNameConfig[mNumGNs];
        for (int i = 0; i < mNumGNs; i++) {
            String name = IGeneralNameUtil.PROP_GENERALNAME + i;
            IConfigStore substore = mConfig.getSubStore(name);

            mGNs[i] = CMS.createSubjAltNameConfig(name, substore, mEnabled);
        }

        // init instance params.
        mInstanceParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mInstanceParams.addElement(
                IGeneralNameUtil.PROP_NUM_GENERALNAMES + "=" + mNumGNs);
        for (int j = 0; j < mGNs.length; j++) {
            mGNs[j].getInstanceParams(mInstanceParams);
        }
    }

    /**
     * Adds the subject alternative names extension if not set already.
     *
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        // Find the X509CertInfo object in the request
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);

            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return res;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        PolicyResult res = PolicyResult.ACCEPTED;

        try {
            // Find the extensions in the certInfo
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            // Remove any previously computed version of the extension
            // unless it is from RA. If from RA, accept what RA put in
            // request and don't add our own.
            if (extensions != null) {
                String sourceId = req.getSourceId();

                if (sourceId != null && sourceId.length() > 0)
                    return res; // accepted
                try {
                    extensions.delete(SubjectAlternativeNameExtension.NAME);
                } catch (IOException e) {
                    // extension isn't there
                }
            }

            // form list of general names for the extension.
            GeneralNames gns = new GeneralNames();

            for (int i = 0; i < mNumGNs; i++) {
                Object value = null;

                value = req.getExtDataInString(mGNs[i].getPfx(), mGNs[i].getAttr());
                if (value == null) {
                    continue;
                }
                Vector<GeneralName> gn = mGNs[i].formGeneralNames(value);

                if (gn.size() == 0)
                    continue;
                for (Enumeration<GeneralName> n = gn.elements(); n.hasMoreElements();) {
                    gns.addElement(n.nextElement());
                }
            }

            // nothing was found in request to put into extension
            if (gns.size() == 0)
                return res; // accepted

            String subject = certInfo.get(X509CertInfo.SUBJECT).toString();

            boolean curCritical = mCritical;

            if (subject.equals("")) {
                curCritical = true;
            }

            // make the extension
            SubjectAlternativeNameExtension sa = new SubjectAlternativeNameExtension(curCritical, gns);

            // add it to certInfo.
            if (extensions == null)
                extensions = createCertificateExtensions(certInfo);

            extensions.set(SubjectAlternativeNameExtension.NAME, sa);

            return res; // accepted.

        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, e.getMessage());
            return PolicyResult.REJECTED; // unrecoverable error.
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED; // unrecoverable error.
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("BASE_INTERNAL_ERROR_1", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Internal Error");
            return PolicyResult.REJECTED; // unrecoverable error.
        }
    }

    /**
     * Create a new SET of extensions in the certificate info
     * object.
     *
     * This should be a method in the X509CertInfo object
     */
    protected CertificateExtensions
            createCertificateExtensions(X509CertInfo certInfo)
                    throws IOException, CertificateException {
        CertificateExtensions extensions;

        // Force version to V3
        certInfo.set(X509CertInfo.VERSION,
                new CertificateVersion(CertificateVersion.V3));

        extensions = new CertificateExtensions();
        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        return extensions;
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
        return mDefParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {

        // extended plugin info.
        Vector<String> info = new Vector<String>();

        info.addElement(PROP_CRITICAL
                + ";boolean;RFC2459 recommendation: If the certificate subject field contains an empty sequence, the extension MUST be marked critical.");
        info.addElement(IGeneralNameUtil.PROP_NUM_GENERALNAMES_INFO);
        for (int i = 0; i < IGeneralNameUtil.DEF_NUM_GENERALNAMES; i++) {
            CMS.getSubjAltNameConfigExtendedPluginInfo(
                    IGeneralNameUtil.PROP_GENERALNAME + i, info);
        }
        info.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-subjaltname");
        info.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";This policy inserts the Subject Alternative Name " +
                "Extension into the certificate. See RFC 2459 (4.2.1.7). " +
                "* Note: you probably want to use this policy in " +
                "conjunction with an authentication manager which sets " +
                "the 'mail' or 'mailalternateaddress' values in the authToken. " +
                "See the 'ldapStringAttrs' parameter in the Directory-based " +
                "authentication plugin");
        mExtendedPluginInfo = new String[info.size()];
        info.copyInto(mExtendedPluginInfo);
        return mExtendedPluginInfo;
    }

}
