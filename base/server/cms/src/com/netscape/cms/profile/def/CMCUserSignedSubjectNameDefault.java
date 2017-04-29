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
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

/**
 * This class implements an enrollment default policy
 * that populates a CMC signing user's subject name
 * into the certificate template.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CMCUserSignedSubjectNameDefault extends EnrollDefault {

    public static final String VAL_NAME = "name";

    public CMCUserSignedSubjectNameDefault() {
        super();
        addValueName(VAL_NAME);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_NAME)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            X500Name x500name = null;

            try {
                x500name = new X500Name(value);
            } catch (IOException e) {
                CMS.debug(e.toString());
                // failed to build x500 name
            }
            CMS.debug("SubjectNameDefault: setValue name=" + x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                CMS.debug("CMCUserSignedSubjectNameDefault: setValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            CertificateSubjectName sn = null;

            try {
                sn = (CertificateSubjectName)
                        info.get(X509CertInfo.SUBJECT);
                return sn.toString();
            } catch (Exception e) {
                // nothing
            }
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_CMC_USER_SIGNED_SUBJECT_NAME");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        String method = "CMCUserSignedSubjectNameDefault: populate: ";
        String msg = "";
        CMS.debug(method + "begins");

        String signingUserSerial = request.getExtDataInString(IAuthManager.CRED_CMC_SIGNING_CERT);
        if (info == null) {
            msg = method + "info null";
            CMS.debug(msg);
            throw new EProfileException(msg);
        }

        CertificateSubjectName certSN = null;
        try {
            certSN = EnrollProfile.getCMCSigningCertSNfromCertSerial(signingUserSerial);
            info.set(X509CertInfo.SUBJECT, certSN);
            CMS.debug(method + "subjectDN set in X509CertInfo");
        } catch (Exception e) {
            msg = method + "exception thrown:" + e;
            throw new EProfileException(e.toString());
        }
        request.setExtData(IEnrollProfile.REQUEST_CERTINFO, info);
        CMS.debug(method + "ends");
    }
}
