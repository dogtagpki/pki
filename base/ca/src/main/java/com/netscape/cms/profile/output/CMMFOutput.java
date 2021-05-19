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

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkix.cmmf.CertOrEncCert;
import org.mozilla.jss.pkix.cmmf.CertRepContent;
import org.mozilla.jss.pkix.cmmf.CertResponse;
import org.mozilla.jss.pkix.cmmf.CertifiedKeyPair;
import org.mozilla.jss.pkix.cmmf.PKIStatusInfo;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertPrettyPrint;

/**
 * This class implements the output plugin that outputs
 * CMMF response for the issued certificate.
 *
 * @version $Revision$, $Date$
 */
public class CMMFOutput extends EnrollOutput {

    public static final String VAL_PRETTY_CERT = "pretty_cert";
    public static final String VAL_CMMF_RESPONSE = "cmmf_response";

    public CMMFOutput() {
        addValueName(VAL_PRETTY_CERT);
        addValueName(VAL_CMMF_RESPONSE);
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
    public void populate(Map<String, String> ctx, IRequest request)
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
        } else if (name.equals(VAL_CMMF_RESPONSE)) {
            return new Descriptor(IDescriptor.PRETTY_PRINT, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_CMMF_B64"));
        }
        return null;
    }

    @Override
    public String getValue(String name, Locale locale, IRequest request)
            throws EProfileException {

        CAEngine engine = CAEngine.getInstance();

        if (name.equals(VAL_PRETTY_CERT)) {
            X509CertImpl cert = request.getExtDataInCert(
                    EnrollProfile.REQUEST_ISSUED_CERT);
            CertPrettyPrint prettyCert = new CertPrettyPrint(cert);

            return prettyCert.toString(locale);
        } else if (name.equals(VAL_CMMF_RESPONSE)) {
            try {
                X509CertImpl cert = request.getExtDataInCert(
                        EnrollProfile.REQUEST_ISSUED_CERT);
                if (cert == null)
                    return null;

                CertificateAuthority ca = engine.getCA();
                CertificateChain cachain = ca.getCACertChain();
                X509Certificate[] cacerts = cachain.getChain();

                byte[][] caPubs = new byte[cacerts.length][];

                for (int j = 0; j < cacerts.length; j++) {
                    caPubs[j] = ((X509CertImpl) cacerts[j]).getEncoded();
                }

                CertRepContent certRepContent = null;
                certRepContent = new CertRepContent(caPubs);

                PKIStatusInfo status = new PKIStatusInfo(PKIStatusInfo.granted);
                CertifiedKeyPair certifiedKP =
                        new CertifiedKeyPair(new CertOrEncCert(cert.getEncoded()));
                CertResponse resp =
                        new CertResponse(new INTEGER(request.getRequestId().toString()),
                                status, certifiedKP);
                certRepContent.addCertResponse(resp);

                ByteArrayOutputStream certRepOut = new ByteArrayOutputStream();
                certRepContent.encode(certRepOut);
                byte[] certRepBytes = certRepOut.toByteArray();

                return Utils.base64encode(certRepBytes, true);
            } catch (Exception e) {
                return null;
            }
        } else {
            return null;
        }
    }

}
