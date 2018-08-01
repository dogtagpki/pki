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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.constraint;

import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.def.AuthTokenSubjectNameDefault;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

/**
 * This class implements the user subject name constraint for self-signed cmc requests.
 * It makes sure the SharedSecret authenticated subjectDN and the rsulting cert match
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CMCSelfSignedSubjectNameConstraint extends EnrollConstraint {

    public CMCSelfSignedSubjectNameConstraint() {
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation. User encoded subject name
     * is copied into the certificate template.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        String method = "CMCSelfSignedSubjectNameConstraint: ";
        String msg = "";

        CertificateSubjectName infoCertSN = null;
        String authTokenSharedTokenSN = null;

        try {
            infoCertSN = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
            if (infoCertSN == null) {
                msg = method + "infoCertSN null";
                CMS.debug(msg);
                throw new Exception(msg);
            }
            CMS.debug(method + "validate user subject ="+
                      infoCertSN.toString());
            X500Name infoCertName = (X500Name) infoCertSN.get(CertificateSubjectName.DN_NAME);
            if (infoCertName == null) {
                msg = method + "infoCertName null";
                CMS.debug(msg);
                throw new Exception(msg);
            }

            authTokenSharedTokenSN = request.getExtDataInString(IAuthToken.TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT);
            if (authTokenSharedTokenSN == null) {
                msg = method + "authTokenSharedTokenSN null";
                CMS.debug(msg);
                throw new Exception(msg);
            }
            if (infoCertName.getName().equalsIgnoreCase(authTokenSharedTokenSN)) {
                CMS.debug(method + "names matched");
            } else {
                msg = method + "names do not match; authTokenSharedTokenSN =" +
                        authTokenSharedTokenSN;
                CMS.debug(msg);
                throw new Exception(msg);
            }

        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED") + e);
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale,
                   "CMS_PROFILE_CONSTRAINT_CMC_SELF_SIGNED_SUBJECT_NAME_TEXT");
    }

    public boolean isApplicable(IPolicyDefault def) {
        String method = "CMCSelfSignedSubjectNameConstraint: isApplicable: ";
        if (def instanceof AuthTokenSubjectNameDefault) {
            CMS.debug(method + "true");
            return true;
        }
        CMS.debug(method + "false");
        return false;
    }
}
