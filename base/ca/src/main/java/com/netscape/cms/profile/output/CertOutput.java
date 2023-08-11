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
import java.util.Map;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements the pretty print certificate output
 * that displays the issued certificate in a pretty print format.
 *
 * @version $Revision$, $Date$
 */
public class CertOutput extends EnrollOutput {
    public static final String VAL_PRETTY_CERT = "pretty_cert";
    public static final String VAL_B64_CERT = "b64_cert";

    public CertOutput() {
        addValueName(VAL_PRETTY_CERT);
        addValueName(VAL_B64_CERT);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_CERT_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, Request request)
            throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
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

    @Override
    public String getValue(String name, Locale locale, Request request)
            throws EProfileException {
        if (name.equals(VAL_PRETTY_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;
            CertPrettyPrint prettyCert = new CertPrettyPrint(cert);

            return prettyCert.toString(locale);
        } else if (name.equals(VAL_B64_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;
            try {
                return CertUtil.toPEM(cert);
            } catch (Exception e) {
                throw new EProfileException(e);
            }
        } else {
            return null;
        }
    }

}
