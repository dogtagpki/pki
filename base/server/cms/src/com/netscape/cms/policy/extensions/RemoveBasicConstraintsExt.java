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

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Remove Basic Constraints policy.
 * Adds the Basic constraints extension.
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
public class RemoveBasicConstraintsExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    public RemoveBasicConstraintsExt() {
        NAME = "RemoveBasicConstraintsExt";
        DESC = "Remove Basic Constraints extension";
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
    }

    public PolicyResult apply(IRequest req) {

        // get cert info.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        X509CertInfo certInfo = null;

        if (ci == null || (certInfo = ci[0]) == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certResult = applyCert(req, certInfo);

            if (certResult == PolicyResult.REJECTED)
                return certResult;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(
            IRequest req, X509CertInfo certInfo) {
        // get basic constraints extension from cert info if any.
        CertificateExtensions extensions = null;

        try {
            // get basic constraints extension if any.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                try {
                    extensions.delete(BasicConstraintsExtension.NAME);
                    CMS.debug("PolicyRule RemoveBasicConstraintsExt: removed the extension from request "
                            + req.getRequestId().toString());
                } catch (IOException e) {
                }
            }
        } catch (IOException e) {
            // no extensions or basic constraints extension.
        } catch (CertificateException e) {
            // no extensions or basic constraints extension.
        }
        return PolicyResult.ACCEPTED;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        return defParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-removebasicconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Removes the Basic Constraints extension."
            };

        return params;
    }

}
