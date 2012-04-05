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
package com.netscape.cms.profile.output;

import java.util.Locale;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This class implements the pretty print certificate output
 * that displays the issued certificate in a pretty print format.
 *
 * @version $Revision$, $Date$
 */
public class CertOutput extends EnrollOutput implements IProfileOutput {
    public static final String VAL_PRETTY_CERT = "pretty_cert";
    public static final String VAL_B64_CERT = "b64_cert";

    public CertOutput() {
        addValueName(VAL_PRETTY_CERT);
        addValueName(VAL_B64_CERT);
    }

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
            throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_PRETTY_CERT)) {
            return new Descriptor(IDescriptor.PRETTY_PRINT, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_CERT_PP"));
        } else if (name.equals(VAL_B64_CERT)) {
            return new Descriptor(IDescriptor.PRETTY_PRINT, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_CERT_B64"));
        }
        return null;
    }

    public String getValue(String name, Locale locale, IRequest request)
            throws EProfileException {
        if (name.equals(VAL_PRETTY_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(
                    EnrollProfile.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;
            ICertPrettyPrint prettyCert = CMS.getCertPrettyPrint(cert);

            return prettyCert.toString(locale);
        } else if (name.equals(VAL_B64_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(
                    EnrollProfile.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;
            return CMS.getEncodedCert(cert);
        } else {
            return null;
        }
    }

}
