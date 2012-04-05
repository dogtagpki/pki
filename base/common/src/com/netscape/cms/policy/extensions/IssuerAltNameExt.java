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
import netscape.security.x509.IssuerAlternativeNameExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.policy.IGeneralNamesConfig;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Issuer Alt Name Extension policy.
 *
 * This extension is used to associate Internet-style identities
 * with the Certificate issuer.
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
public class IssuerAltNameExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    public static final String PROP_CRITICAL = "critical";

    // PKIX specifies the that the extension SHOULD NOT be critical
    public static final boolean DEFAULT_CRITICALITY = false;

    private static Vector<String> defaultParams = new Vector<String>();
    private static String[] mInfo = null;

    static {
        defaultParams.addElement(PROP_CRITICAL + "=" + DEFAULT_CRITICALITY);
        CMS.getGeneralNamesConfigDefaultParams(null, true, defaultParams);

        Vector<String> info = new Vector<String>();

        info.addElement(PROP_CRITICAL + ";boolean;RFC 2459 recommendation: SHOULD NOT be marked critical.");
        info.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-issueraltname");
        info.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";This policy inserts the Issuer Alternative Name " +
                "Extension into the certificate. See RFC 2459 (4.2.1.8). ");

        CMS.getGeneralNamesConfigExtendedPluginInfo(null, true, info);

        mInfo = new String[info.size()];
        info.copyInto(mInfo);
    }

    private Vector<String> mParams = new Vector<String>();
    private IConfigStore mConfig = null;
    private boolean mCritical = DEFAULT_CRITICALITY;
    private boolean mEnabled = false;
    IGeneralNamesConfig mGNs = null;
    IssuerAlternativeNameExtension mExtension = null;

    /**
     * Adds the issuer alternate name extension to all certs.
     */
    public IssuerAltNameExt() {
        NAME = "IssuerAltNameExt";
        DESC = "Associate Internet-style Identities with Issuer";
    }

    /**
     * Initializes this policy rule.
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        // get criticality
        mCritical = mConfig.getBoolean(PROP_CRITICAL, DEFAULT_CRITICALITY);

        // get enabled.
        mEnabled = mConfig.getBoolean(
                    IPolicyProcessor.PROP_ENABLE, false);

        // form general names.
        mGNs = CMS.createGeneralNamesConfig(null, config, true, mEnabled);

        // form extension
        try {
            if (mEnabled &&
                    mGNs.getGeneralNames() != null && !mGNs.getGeneralNames().isEmpty()) {
                mExtension =
                        new IssuerAlternativeNameExtension(
                                Boolean.valueOf(mCritical), mGNs.getGeneralNames());
            }
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        // init instance params
        mParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mGNs.getInstanceParams(mParams);

        return;
    }

    /**
     * Adds a extension if none exists.
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        if (mEnabled == false || mExtension == null)
            return res;

        // get cert info.
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
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        // get extension from cert info if any.
        CertificateExtensions extensions = null;

        try {
            // get extension if any.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
            // no extensions.
        } catch (CertificateException e) {
            // no extension.
        }

        if (extensions == null) {
            extensions = new CertificateExtensions();
            try {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } catch (CertificateException e) {
                // not possible
            } catch (Exception e) {
            }
        } else {

            // remove any previously computed version of the extension
            try {
                extensions.delete(IssuerAlternativeNameExtension.NAME);

            } catch (IOException e) {
                // this is the hack
                // If name is not found, try deleting using the OID

                try {
                    extensions.delete("2.5.29.18");
                } catch (IOException ee) {
                }
            }
        }

        try {
            extensions.set(IssuerAlternativeNameExtension.NAME, mExtension);
        } catch (Exception e) {
            if (e instanceof RuntimeException)
                throw (RuntimeException) e;
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CRL_CREATE_ISSUER_ALT_NAME_EXT", e.toString()));
            setError(req, CMS.getUserMessage("CMS_POLICY_SUBJECT_KEY_ID_ERROR"), NAME);
            return PolicyResult.REJECTED;
        }
        return PolicyResult.ACCEPTED;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return Empty Vector since this policy has no configuration parameters.
     *         for this policy instance.
     */
    public Vector<String> getInstanceParams() {
        return mParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return Empty Vector since this policy implementation has no
     *         configuration parameters.
     */
    public Vector<String> getDefaultParams() {
        return defaultParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        return mInfo;
    }

}
