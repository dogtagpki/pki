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

import org.dogtagpki.server.authentication.AuthManager;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.def.CMCUserSignedSubjectNameDefault;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the user subject name constraint for user-signed cmc requests.
 * It makes sure the signing cert's subjectDN and the rsulting cert match
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CMCUserSignedSubjectNameConstraint extends EnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMCUserSignedSubjectNameConstraint.class);

    public CMCUserSignedSubjectNameConstraint() {
    }

    @Override
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
    @Override
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        String method = "CMCUserSignedSubjectNameConstraint: ";
        String msg = "";

        logger.debug(method + "validate start");
        CertificateSubjectName infoCertSN = null;
            CertificateSubjectName authTokenCertSN = null;


        try {
            infoCertSN = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
            if (infoCertSN == null) {
                msg = method + "infoCertSN null";
                logger.error(msg);
                throw new Exception(msg);
            }
            logger.debug(method + "validate user subject=" + infoCertSN);
            String certSerial = request.getExtDataInString(AuthManager.CRED_CMC_SIGNING_CERT);
            if (certSerial == null) {
                msg = method + "certSerial null";
                logger.error(msg);
                throw new Exception(msg);
            }
            authTokenCertSN =
                          EnrollProfile.getCMCSigningCertSNfromCertSerial(certSerial);
            if (authTokenCertSN == null) {
                msg = method + "authTokenCertSN null";
                logger.error(msg);
                throw new Exception(msg);
            }
            X500Name infoCertName = (X500Name) infoCertSN.get(CertificateSubjectName.DN_NAME);
            if (infoCertName == null) {
                msg = method + "infoCertName null";
                logger.error(msg);
                throw new Exception(msg);
            }
            X500Name authTokenCertName = (X500Name) authTokenCertSN.get(CertificateSubjectName.DN_NAME);
            if (authTokenCertName == null) {
                msg = method + "authTokenCertName null";
                logger.error(msg);
                throw new Exception(msg);
            }
            if (infoCertName.equals(authTokenCertName)) {
                logger.debug(method + "names match");
            } else {
                msg = method + "names do not match";
                logger.error(msg);
                throw new Exception(msg);
            }

        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED") + e);
        }
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale,
                   "CMS_PROFILE_CONSTRAINT_CMC_USER_SIGNED_SUBJECT_NAME_TEXT");
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
        String method = "CMCUserSignedSubjectNameConstraint: isApplicable: ";
        if (def instanceof CMCUserSignedSubjectNameDefault) {
            logger.debug(method + "true");
            return true;
        }
        logger.debug(method + "false");
        return false;
    }
}
