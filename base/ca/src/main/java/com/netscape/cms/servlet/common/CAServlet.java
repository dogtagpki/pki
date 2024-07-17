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
package com.netscape.cms.servlet.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;

public abstract class CAServlet extends CMSServlet {

    protected boolean checkImportCertToNav(
            HttpServletResponse httpResp,
            ArgBlock httpParams,
            X509CertImpl cert)
            throws EBaseException {

        if (!httpParams.getValueAsBoolean(IMPORT_CERT, false)) {
            return false;
        }

        boolean importCAChain = httpParams.getValueAsBoolean(IMPORT_CHAIN, true);

        // XXX Temporary workaround because of problem with passing Mime type
        boolean emailCert = httpParams.getValueAsBoolean("emailCert", false);

        String importMimeType = emailCert ?
                httpParams.getValueAsString(IMPORT_CERT_MIME_TYPE, NS_X509_EMAIL_CERT) :
                httpParams.getValueAsString(IMPORT_CERT_MIME_TYPE, NS_X509_USER_CERT);

        // String importMimeType = httpParams.getValueAsString(
        //     IMPORT_CERT_MIME_TYPE, NS_X509_USER_CERT);
        importCertToNav(httpResp, cert, importMimeType, importCAChain);

        return true;
    }

    /**
     * handy routine to import cert to old navigator in nav mime type.
     */
    public void importCertToNav(
            HttpServletResponse httpResp,
            X509CertImpl cert,
            String contentType,
            boolean importCAChain)
            throws EBaseException {

        ServletOutputStream out = null;
        byte[] encoding = null;

        logger.debug("CMSServlet: importCertToNav " +
                       "contentType=" + contentType + " " +
                       "importCAChain=" + importCAChain);

        try {
            out = httpResp.getOutputStream();

            if (importCAChain) {
                CertificateChain caChain = null;
                X509Certificate[] caCerts = null;
                PKCS7 p7 = null;

                CAEngine engine = CAEngine.getInstance();
                CertificateAuthority ca = engine.getCA();
                caChain = ca.getCACertChain();
                caCerts = caChain.getChain();

                // set user + CA cert chain in pkcs7
                X509CertImpl[] userChain = new X509CertImpl[caCerts.length + 1];

                userChain[0] = cert;
                int m = 1, n = 0;

                for (; n < caCerts.length; m++, n++) {
                    userChain[m] = (X509CertImpl) caCerts[n];

                    // logger.debug("CAServlet: cert " + m + ": " + userChain[m]);
                }

                p7 = new PKCS7(new AlgorithmId[0],
                            new ContentInfo(new byte[0]),
                            userChain,
                            new SignerInfo[0]);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                p7.encodeSignedData(bos, false);
                encoding = bos.toByteArray();
                logger.debug("CMServlet: return P7 " + Utils.base64encode(encoding, true));

            } else {
                encoding = cert.getEncoded();
                logger.debug("CMServlet: return Certificate " + Utils.base64encode(encoding, true));
            }

            httpResp.setContentType(contentType);
            out.write(encoding);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_RET_CERT_IMPORT_ERR", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_RETURNING_CERT"), e);

        } catch (CertificateEncodingException e) {
            logger.error(CMS.getLogMessage("CMSGW_NO_ENCODED_IMP_CERT", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"), e);
        }
    }

    protected boolean isSystemCertificate(BigInteger serialNo) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        X509Certificate caCert = ca.getCACert();

        if (caCert != null) {
            /* only check this if we are self-signed */
            if (caCert.getSubjectDN().equals(caCert.getIssuerDN())) {
                if (caCert.getSerialNumber().equals(serialNo)) {
                    return true;
                }
            }
        }

        return false;
    }
}
