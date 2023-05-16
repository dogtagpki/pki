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

import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements the output plugin that outputs
 * PKCS7 for the issued certificate.
 *
 * @version $Revision$, $Date$
 */
public class PKCS7Output extends EnrollOutput {

    public static final String VAL_PRETTY_CERT = "pretty_cert";
    public static final String VAL_PKCS7 = "pkcs7";

    public PKCS7Output() {
        addValueName(VAL_PRETTY_CERT);
        addValueName(VAL_PKCS7);
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
        } else if (name.equals(VAL_PKCS7)) {
            return new Descriptor(IDescriptor.PRETTY_PRINT, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_PKCS7_B64"));
        }
        return null;
    }

    @Override
    public String getValue(String name, Locale locale, Request request)
            throws EProfileException {

        CAEngine engine = CAEngine.getInstance();

        if (name.equals(VAL_PRETTY_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;
            CertPrettyPrint prettyCert = new CertPrettyPrint(cert);

            return prettyCert.toString(locale);
        } else if (name.equals(VAL_PKCS7)) {

            try {
                X509CertImpl cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                if (cert == null)
                    return null;

                CertificateAuthority ca = engine.getCA();
                CertificateChain cachain = ca.getCACertChain();
                X509Certificate[] cacerts = cachain.getChain();

                X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
                int m = 1, n = 0;

                for (; n < cacerts.length; m++, n++) {
                    userChain[m] = (X509CertImpl) cacerts[n];
                }

                userChain[0] = cert;
                PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                        new ContentInfo(new byte[0]),
                        userChain,
                        new SignerInfo[0]);

                byte[] p7Bytes = p7.getBytes();
                String p7Str = Utils.base64encode(p7Bytes, true);

                return p7Str;
            } catch (Exception e) {
                return "";
            }
        } else {
            return null;
        }
    }

}
