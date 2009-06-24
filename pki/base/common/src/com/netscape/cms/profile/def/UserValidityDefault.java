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


import java.io.*;
import java.math.*;
import java.util.*;
import com.netscape.cms.profile.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.apps.CMS;

import java.security.interfaces.DSAParams;
import netscape.security.x509.*;
import netscape.security.provider.*;


/**
 * This class implements an enrollment default policy
 * that populates a user-supplied validity
 * into the certificate template.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class UserValidityDefault extends EnrollDefault {

    public static final String VAL_NOT_BEFORE = "userValdityNotBefore";
    public static final String VAL_NOT_AFTER = "userValdityNotAfter";

    public UserValidityDefault() {
        super();
        addValueName(VAL_NOT_BEFORE);
        addValueName(VAL_NOT_AFTER);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_NOT_BEFORE)) {
            return new Descriptor(IDescriptor.STRING, 
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_BEFORE"));
        } else if (name.equals(VAL_NOT_AFTER)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_NOT_AFTER"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
        X509CertInfo info, String value)
        throws EPropertyException {
        // this default rule is readonly
    }

    public String getValue(String name, Locale locale,
        X509CertInfo info)
        throws EPropertyException {
        if (name == null) { 
            throw new EPropertyException(CMS.getUserMessage( 
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NOT_BEFORE)) {
            CertificateValidity validity = null;

            try {
                validity = (CertificateValidity)
                   info.get(X509CertInfo.VALIDITY);
                Date notBefore = (Date)
                    validity.get(CertificateValidity.NOT_BEFORE);

                return notBefore.toString();
            } catch (Exception e) {
                CMS.debug("UserValidityDefault: getValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage( 
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else if (name.equals(VAL_NOT_AFTER)) {
            try {
                CertificateValidity validity = null;
                validity = (CertificateValidity)
                   info.get(X509CertInfo.VALIDITY);
                Date notAfter = (Date)
                    validity.get(CertificateValidity.NOT_AFTER);

                return notAfter.toString();
            } catch (Exception e) {
                CMS.debug("UserValidityDefault: getValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage( 
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage( 
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_VALIDITY");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
        throws EProfileException {
        CertificateValidity certValidity = null;
        // authenticate the certificate key, and move
        // the key from request into x509 certinfo
        try {
            byte[] certValidityData = request.getExtDataInByteArray(
                    IEnrollProfile.REQUEST_VALIDITY);
            if (certValidityData != null) {
                certValidity = new CertificateValidity();
                certValidity.decode(
                        new ByteArrayInputStream(certValidityData));
            }
            info.set(X509CertInfo.VALIDITY, certValidity);
        } catch (Exception e) {
            CMS.debug("UserValidityDefault: populate " + e.toString());
        }
    }
}
