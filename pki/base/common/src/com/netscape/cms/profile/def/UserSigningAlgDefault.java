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

//import java.security.interfaces.DSAParams;
import netscape.security.x509.*;
//import netscape.security.provider.*;


/**
 * This class implements an enrollment default policy
 * that populates a user-supplied signing algorithm
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class UserSigningAlgDefault extends EnrollDefault {

    public static final String VAL_ALG_ID = "userSigningAlgID";

    public UserSigningAlgDefault() {
        super();
        addValueName(VAL_ALG_ID);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_ALG_ID)) {
            return new Descriptor(IDescriptor.STRING, 
                    IDescriptor.READONLY, null,
                    CMS.getUserMessage(locale,
                        "CMS_PROFILE_SIGNING_ALGORITHM"));
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
        if (name.equals(VAL_ALG_ID)) {
            CertificateAlgorithmId algID = null;

            try {
                algID = (CertificateAlgorithmId)
                        info.get(X509CertInfo.ALGORITHM_ID);
                AlgorithmId id = (AlgorithmId)
                    algID.get(CertificateAlgorithmId.ALGORITHM);

                return id.toString();
            } catch (Exception e) {
                CMS.debug("UserSigningAlgDefault: setValue " + e.toString());
                return ""; //XXX
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_SIGNING_ALGORITHM");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
        throws EProfileException {
        CertificateAlgorithmId certAlg = null;
        // authenticate the certificate key, and move
        // the key from request into x509 certinfo
        try {
            byte[] certAlgData = request.getExtDataInByteArray(
                    IEnrollProfile.REQUEST_SIGNING_ALGORITHM);
            if (certAlgData != null) {
                certAlg = new CertificateAlgorithmId(
                        new ByteArrayInputStream(certAlgData));
            }
            info.set(X509CertInfo.ALGORITHM_ID, certAlg);
        } catch (Exception e) {
            CMS.debug("UserSigningAlgDefault: populate " + e.toString());
        }
    }
}
