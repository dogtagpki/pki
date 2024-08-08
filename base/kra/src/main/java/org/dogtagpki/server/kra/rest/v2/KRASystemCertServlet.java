package org.dogtagpki.server.kra.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.cert.CertData;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
@WebServlet(
        name = "kraSystemCert",
        urlPatterns = "/v2/config/cert/*")
public class KRASystemCertServlet extends KRAServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(KRASystemCertServlet.class);

    @WebAction(method = HttpMethod.GET, paths = { "transport"})
    public void getTransportCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRASystemCertServlet.getTransportCert(): session: {}", session.getId());

        X509Certificate[] chain = transportUnit.getChain();
        X509CertImpl[] chainImpl = new X509CertImpl[chain.length];

        for (int i=0; i<chain.length; i++) {
            X509Certificate c = chain[i];
            chainImpl[i] = new X509CertImpl(c.getEncoded());
        }

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                chainImpl,
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
