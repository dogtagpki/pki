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
    public static final String CONFIG_USE_SYS_ENCODING = "useSysEncoding";

    public UserSubjectNameDefault() {
        super();
        addConfigName(CONFIG_USE_SYS_ENCODING);
        addValueName(VAL_NAME);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_USE_SYS_ENCODING)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CONFIG_USE_SYS_ENCODING"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_NAME)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME"));
        } else {
            return null;
        }
    }

    private X500Name getX500Name(X509CertInfo info, String value) {
            String method = "UserSubjectNameDefault: getX500Name: ";
            X500Name x500name = null;
            /*
             * useSysEencoding default is false
             * To change that, add the following in the affected profile:
             * policyset.<policy set>.<#>.default.params.useSysEncoding=true
             */
            boolean useSysEncoding = getConfigBoolean(CONFIG_USE_SYS_ENCODING);
            CMS.debug(method +
                    "use system encoding: " + useSysEncoding);

            try {
                if (value != null)
                    x500name = new X500Name(value);

                // oldName is what comes with the CSR
                CertificateSubjectName oldName = info.getSubjectObj();
                if (oldName != null) {
                    CMS.debug(method + "subjectDN exists in CSR. ");
                } else {
                    CMS.debug(method + "subjectDN does not exist in CSR. ");
                }
                if ((useSysEncoding == false) && (oldName != null)) {
                    /* If the canonical string representations of
                     * existing Subject DN and new DN are equal,
                     * keep the old name so that the attribute
                     * encodings are preserved. */
                    X500Name oldX500name = oldName.getX500Name();
                    if (x500name == null) {
                        CMS.debug( method
                            + "new Subject DN is null; "
                            + "retaining current value."
                        );
                        x500name = oldX500name;
                    } else if (x500name.toString().equals(oldX500name.toString())) {
                        CMS.debug( method
                            + "new Subject DN has same string representation "
                            + "as current value; retaining current value."
                        );
                        x500name = oldX500name;
                    } else {
                        CMS.debug(method
                            + "replacing current value `" + oldX500name.toString() + "` "
                            + "with new value `" + x500name.toString() + "`"
                        );
                    }
                }
            } catch (IOException e) {
                CMS.debug(method + e.toString());
                // failed to build x500 name
            }
            return x500name;
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        String method = "UserSubjectNameDefault: setValue: ";
        if (name == null) {
            CMS.debug(name + "name null");
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        CMS.debug(method + "name = " + name);
        if (value != null)
            CMS.debug(method + "value = " + value);
        else
            CMS.debug(method + "value = null");

        if (name.equals(VAL_NAME)) {
            X500Name x500name = getX500Name(info, value);
            CMS.debug(method + "setting name=" + x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                CMS.debug(method + e.toString());
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
        CertificateSubjectName req_sbj = request.getExtDataInCertSubjectName(
                    IEnrollProfile.REQUEST_SUBJECT_NAME);
        if (req_sbj == null) {
            // failed to retrieve subject name
            CMS.debug("UserSubjectNameDefault: populate req_sbj is null");
            throw new EProfileException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
        try {
            info.set(X509CertInfo.SUBJECT, req_sbj);

            // see if the encoding needs changing
            X500Name x500name = getX500Name(info, req_sbj.toString());
            if (x500name != null) {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            }
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("UserSubjectNameDefault: populate " + e.toString());
            throw new EProfileException(e.toString());
        }
    }
}
