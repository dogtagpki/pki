//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.WebAction;

/**
 * ACME certificate.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeCertificateServlet",
        urlPatterns = "/cert/*")
public class ACMECertificateServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMECertificateServlet.class);

    @WebAction(method = HttpMethod.GET, paths = { "{}"})
    public void getCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        handleCertificate(request, response);
    }

    @WebAction(method = HttpMethod.POST, paths = { "{}"})
    public void postgetCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        handleCertificate(request, response);
    }


    public void handleCertificate(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String certID = pathElement[0];

        logger.info("Retrieving certificate " + certID);

        ACMEIssuer issuer = engine.getIssuer();
        String certChain = issuer.getCertificateChain(certID);

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);

        response.setContentType(MimeType.APPLICATION_PEM_CERTIFICATE_CHAIN);
        PrintWriter out = response.getWriter();
        out.println(certChain);
    }

}
