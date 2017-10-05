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
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a user-supplied subject name
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class UserSubjectNameDefault extends EnrollDefault {

    public static final String VAL_NAME = "name";

    public UserSubjectNameDefault() {
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

                CertificateSubjectName oldName = info.getSubjectObj();
                if (oldName != null) {
                    /* If the canonical string representations of
                     * existing Subject DN and new DN are equal,
                     * keep the old name so that the attribute
                     * encodings are preserved. */
                    X500Name oldX500name = oldName.getX500Name();
                    if (x500name.toString().equals(oldX500name.toString())) {
                        CMS.debug(
                            "UserSubjectNameDefault: setValue: "
                            + "new Subject DN has same string representation "
                            + "as current value; retaining current value."
                        );
                        x500name = oldX500name;
                    } else {
                        CMS.debug(
                            "UserSubjectNameDefault: setValue: "
                            + "replacing current value `" + oldX500name.toString() + "` "
                            + "with new value `" + x500name.toString() + "`"
                        );
                    }
                }
            } catch (IOException e) {
                CMS.debug(e.toString());
                // failed to build x500 name
            }
            CMS.debug("UserSubjectNameDefault: setValue name=" + x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                CMS.debug("UserSubjectNameDefault: setValue " + e.toString());
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
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_SUBJECT_NAME");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        // authenticate the subject name and populate it
        // to the certinfo
        try {
            info.set(X509CertInfo.SUBJECT, request.getExtDataInCertSubjectName(
                    IEnrollProfile.REQUEST_SUBJECT_NAME));
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("UserSubjectNameDefault: populate " + e.toString());
            throw new EProfileException(e.toString());
        }
    }
}
