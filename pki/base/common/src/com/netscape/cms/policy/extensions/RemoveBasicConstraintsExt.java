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


import java.util.*;
import java.io.*;
import java.security.cert.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.logging.ILogger;
import netscape.security.x509.*;
import netscape.ldap.*;
import com.netscape.cms.policy.APolicyRule;


/**
 * Remove Basic Constraints policy.
 * Adds the Basic constraints extension.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
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
        PolicyResult res = PolicyResult.ACCEPTED;

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
                    CMS.debug("PolicyRule RemoveBasicConstraintsExt: removed the extension from request " + req.getRequestId().toString());
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
    public Vector getInstanceParams() { 
        Vector params = new Vector();

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector getDefaultParams() { 
        Vector defParams = new Vector();

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

