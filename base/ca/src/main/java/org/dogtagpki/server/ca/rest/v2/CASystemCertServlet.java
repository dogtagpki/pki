//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
@WebServlet(
        name = "caSystemCert",
        urlPatterns = "/v2/config/cert/*")
public class CASystemCertServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CASystemCertServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {"signing"})
    public void getSigningCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        CertificateAuthority ca = engine.getCA();
        CASigningUnit su = ca.getSigningUnit();

        X509Certificate signingCert = su.getCert();
        X509CertImpl cert = new X509CertImpl(signingCert.getEncoded());
        java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);
        String reqETag = request.getHeader("If-None-Match");
        String eTag = Integer.toString(certData.hashCode());
        response.addHeader("ETag", "\"" + eTag + "\"");
        response.addHeader("Cache-control", "no-transform, max-age=" + DEFAULT_LONG_CACHE_LIFETIME);
        if (reqETag != null &&
                (reqETag.equals(eTag) || reqETag.equals("\"" + eTag + "\""))) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        PrintWriter out = response.getWriter();
        out.println(certData.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"transport"})
    public void getTransportCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        KRAConnectorProcessor processor = new KRAConnectorProcessor(request.getLocale());
        processor.setCMSEngine(engine);
        processor.init();

        KRAConnectorInfo info = processor.getConnectorInfo();

        String encodedCert = info.getTransportCert();
        byte[] bytes = Utils.base64decode(encodedCert);
        X509CertImpl cert = new X509CertImpl(bytes);
        java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);
        String reqETag = request.getHeader("If-None-Match");
        String eTag = Integer.toString(certData.hashCode());
        response.addHeader("ETag", "\"" + eTag + "\"");
        response.addHeader("Cache-control", "no-transform, max-age=" + DEFAULT_LONG_CACHE_LIFETIME);
        if (reqETag != null &&
                (reqETag.equals(eTag) || reqETag.equals("\"" + eTag + "\""))) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        PrintWriter out = response.getWriter();
        out.println(certData.toJSON());
    }
}
