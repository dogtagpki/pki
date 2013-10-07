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

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy that
 * populates subject name based on the attribute values
 * in the authentication token (AuthToken) object.
 *
 * @version $Revision$, $Date$
 */
public class AuthTokenSubjectNameDefault extends EnrollDefault {

    public static final String VAL_NAME = "name";

    public AuthTokenSubjectNameDefault() {
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
        CMS.debug("AuthTokenSubjectNameDefault: begins");
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(locale,
                        "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            X500Name x500name = null;

            try {
                x500name = new X500Name(value);
                CMS.debug("AuthTokenSubjectNameDefault: setValue x500name=" + x500name.toString());
            } catch (IOException e) {
                CMS.debug("AuthTokenSubjectNameDefault: setValue " +
                        e.toString());
                // failed to build x500 name
            }
            CMS.debug("AuthTokenSubjectNameDefault: setValue name=" + x500name.toString());
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                CMS.debug("AuthTokenSubjectNameDefault: setValue " +
                        e.toString());
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(locale,
                        "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null)
            throw new EPropertyException("Invalid name " + name);
        if (name.equals(VAL_NAME)) {
            CertificateSubjectName sn = null;

            try {
                sn = (CertificateSubjectName)
                        info.get(X509CertInfo.SUBJECT);
                return sn.toString();
            } catch (Exception e) {
                // nothing
                CMS.debug("AuthTokenSubjectNameDefault: getValue " +
                        e.toString());
            }
            throw new EPropertyException(CMS.getUserMessage(locale,
                        "CMS_INVALID_PROPERTY", name));
        } else {
            throw new EPropertyException(CMS.getUserMessage(locale,
                        "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_AUTHTOKEN_SUBJECT_NAME");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {

        // authenticate the subject name and populate it
        // to the certinfo
        try {
            X500Name name = new X500Name(
                    request.getExtDataInString(IProfileAuthenticator.AUTHENTICATED_NAME));

            CMS.debug("AuthTokenSubjectNameDefault: X500Name=" + name.toString());
            info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(name));
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("AuthTokenSubjectNameDefault: " + e.toString());
            throw new EProfileException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
    }
}
