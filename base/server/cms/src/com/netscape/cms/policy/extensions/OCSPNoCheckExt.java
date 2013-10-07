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

import netscape.security.extensions.OCSPNoCheckExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * This implements an OCSP Signing policy, it
 * adds the OCSP Signing extension to the certificate.
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
public class OCSPNoCheckExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    public static final String PROP_CRITICAL = "critical";
    private boolean mCritical = false;

    // PKIX specifies the that the extension SHOULD NOT be critical
    public static final boolean DEFAULT_CRITICALITY = false;

    private OCSPNoCheckExtension mOCSPNoCheck = null;

    /**
     * Constructs an OCSP No check extension.
     */
    public OCSPNoCheckExt() {
        NAME = "OCSPNoCheckExt";
        DESC = "Sets OCSPNoCheck extension for certificates";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;RFC 2560 recommendation: SHOULD be non-critical.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-ocspnocheck",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds OCSP signing extension to certificate"
            };

        return params;

    }

    /**
     * Performs one-time initialization of the policy.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mOCSPNoCheck = new OCSPNoCheckExtension();

        if (mOCSPNoCheck != null) {
            // configure the extension itself
            mCritical = config.getBoolean(PROP_CRITICAL,
                        DEFAULT_CRITICALITY);
            mOCSPNoCheck.setCritical(mCritical);
        }
    }

    /**
     * Applies the policy to the given request.
     */
    public PolicyResult apply(IRequest req) {

        // if the extension was not configured correctly, just skip it
        if (mOCSPNoCheck == null) {
            return PolicyResult.ACCEPTED;
        }

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
        try {

            // find the extensions in the certInfo
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            // prepare the extensions data structure
            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } else {
                try {
                    extensions.delete(OCSPNoCheckExtension.NAME);
                } catch (IOException ex) {
                    // OCSPNoCheck extension is not already there
                    //  log(ILogger.LL_FAILURE, "No previous extension: "+OCSPNoCheckExtension.NAME+" "+ex.getMessage());
                }
            }

            extensions.set(OCSPNoCheckExtension.NAME, mOCSPNoCheck);

            return PolicyResult.ACCEPTED;

        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        }
    }

    /**
     * Returns instance parameters.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_CRITICAL + "=" + mCritical);
        return params;

    }

    /**
     * Returns default parameters.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");
        return defParams;

    }
}
