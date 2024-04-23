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
package org.dogtagpki.legacy.server.policy.extensions;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Vector;

import org.dogtagpki.legacy.policy.EnrollmentPolicy;
import org.dogtagpki.legacy.policy.PolicyProcessor;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

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
 * @version $Revision$, $Date$
 */
public class RemoveBasicConstraintsExt extends EnrollmentPolicy implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RemoveBasicConstraintsExt.class);

    public RemoveBasicConstraintsExt() {
        NAME = "RemoveBasicConstraintsExt";
        DESC = "Remove Basic Constraints extension";
    }

    @Override
    public void init(PolicyProcessor owner, ConfigStore config) throws EBaseException {
    }

    @Override
    public PolicyResult apply(Request req) {

        // get cert info.
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(Request.CERT_INFO);

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
            Request req, X509CertInfo certInfo) {
        // get basic constraints extension from cert info if any.
        CertificateExtensions extensions = null;

        try {
            // get basic constraints extension if any.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                try {
                    extensions.delete(BasicConstraintsExtension.NAME);
                    logger.debug("PolicyRule RemoveBasicConstraintsExt: removed the extension from request "
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
    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<>();

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<>();

        return defParams;
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String[] params = {
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-removebasicconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Removes the Basic Constraints extension."
            };

        return params;
    }

}
