//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Globals;
import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.common.AppInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.slf4j.Logger;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.base.UnsupportedMediaType;
import com.netscape.certsrv.base.WebAction;

/**
 * The EST API frontend.
 *
 * @author Fraser Tweedale
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author cfu (added /fullcmc support)
 */
@WebServlet(
        name = "estServlet",
        urlPatterns = "/*")
public class ESTServlet extends org.dogtagpki.server.rest.v2.PKIServlet {
    public static Logger logger = org.slf4j.LoggerFactory.getLogger(ESTServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {"", "info"})
    public void basePage(HttpServletRequest request, HttpServletResponse response) throws Exception {
        AppInfo info = new AppInfo();
        info.setID("est");
        info.setName("Enrollment over Secure Transport");
        info.setPath("/.well-known/est");
        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"cacerts", "{}/cacerts"})
    public void cacerts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        Optional<String> aid = pathElement.length == 2 ? Optional.of(pathElement[0]) : Optional.empty();
        logger.debug("ESTFrontend.cacerts: processing request (label: {})", aid.orElse("None"));
        byte[] certs = cacerts(aid);
        response.setContentType(MimeType.APPLICATION_PKCS7);
        OutputStream out = response.getOutputStream();
        out.write(certs);
    }

    @WebAction(method = HttpMethod.POST, paths = {"simpleenroll", "{}/simpleenroll"})
    public void simpleenroll(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        Optional<String> aid = pathElement.length == 2 ? Optional.of(pathElement[0]) : Optional.empty();
        logger.debug("ESTFrontend.simpleenroll: processing request (label: {})", aid.orElse("None"));

        if (!request.getContentType().toLowerCase().startsWith(MimeType.APPLICATION_PKCS10)) {
            throw new UnsupportedMediaType("Unsupported :" + request.getContentType());
        }
        ESTRequestAuthorizationData authzData = makeAuthzData(aid, request);
        InputStream is = request.getInputStream();
        byte[] data = is.readAllBytes();
        byte[] certs = enroll(aid, authzData, data);
        response.setContentType(MimeType.APPLICATION_PKCS7 + "; smime-type=certs-only");
        OutputStream out = response.getOutputStream();
        out.write(certs);
    }

    @WebAction(method = HttpMethod.POST, paths = {"simplereenroll", "{}/simplereenroll"})
    public void simplereenroll(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        Optional<String> aid = pathElement.length == 2 ? Optional.of(pathElement[0]) : Optional.empty();
        logger.debug("ESTFrontend.simplereenroll: processing request (label: {})", aid.orElse("None"));
        if (!request.getContentType().toLowerCase().startsWith(MimeType.APPLICATION_PKCS10)) {
            throw new UnsupportedMediaType("Unsupported :" + request.getContentType());
        }
        ESTRequestAuthorizationData authzData = makeAuthzData(aid, request);
        InputStream is = request.getInputStream();
        byte[] data = is.readAllBytes();
        byte[] certs = reenroll(aid, authzData, data);
        response.setContentType(MimeType.APPLICATION_PKCS7 + "; smime-type=certs-only");
        OutputStream out = response.getOutputStream();
        out.write(certs);
    }

    @WebAction(method = HttpMethod.POST, paths = {"fullcmc", "{}/fullcmc"})
    public void fullcmc(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        Optional<String> aid = pathElement.length == 2 ? Optional.of(pathElement[0]) : Optional.empty();
        logger.debug("ESTFrontend.fullcmc: processing request (label: {})", aid.orElse("None"));

        // RFC 7030 section 4.3.1:
        //   full cmc request Content-Type should be application/pkcs7-mime
        //   with smime-type=CMC-request
        String contentType = request.getContentType();
        if (contentType == null) {
            throw new UnsupportedMediaType("Content-Type header is required");
        }
        String contentTypeLower = contentType.toLowerCase();
        if (!contentTypeLower.startsWith(MimeType.APPLICATION_PKCS7)) {
            throw new UnsupportedMediaType("Unsupported Content-Type: " + request.getContentType());
        }
        // RFC 7030 Section 4.3.1 requires smime-type=CMC-request
        if (!contentTypeLower.contains("smime-type=cmc-request")) {
            throw new UnsupportedMediaType("Missing required smime-type=CMC-request parameter in Content-Type: " + request.getContentType());
        }

        ESTRequestAuthorizationData authzData = makeAuthzData(aid, request);
        InputStream is = request.getInputStream();
        byte[] data = is.readAllBytes();
        byte[] cmcResponse = fullcmc(aid, authzData, data);

        // Map CMC status to HTTP status code (RFC 7030/8951)
        Integer cmcStatus = getBackend().getLastCMCStatus();
        if (cmcStatus == null) {
            throw new PKIException("CMC status not available from backend - this is a bug");
        }
        int httpStatus = mapCMCStatusToHTTP(cmcStatus);
        response.setStatus(httpStatus);
        logger.debug("ESTServlet.fullcmc: CMC status {} mapped to HTTP {}", cmcStatus, httpStatus);

        // RFC 8951 section 3.2.3:
        //   Response body is base64 encoding of the PKI Response
        // RFC 7030 section 4.3.2:
        //   Response Content-Type is application/pkcs7-mime
        //   with smime-type=CMC-response
        response.setContentType(MimeType.APPLICATION_PKCS7 + "; smime-type=CMC-response");
        OutputStream out = response.getOutputStream();
        out.write(Base64.encodeBase64(cmcResponse, true /* wrap output */));
    }

    private byte[] enroll(Optional<String> label, ESTRequestAuthorizationData authzData, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);

        Object authzResult = getRequestAuthorizer().authorizeSimpleenroll(authzData, csr);

        X509Certificate cert = getBackend().simpleenroll(label, csr, authzData, authzResult);
        return certResponse(cert);
    }

    private byte[] reenroll(Optional<String> label, ESTRequestAuthorizationData authzData, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);

        // TODO implement interface for retrieval of to-be-renewed cert.
        // For now, we unconditionally use the client certificate (if available).
        X509Certificate toBeRenewed = null;
        if (authzData.clientCertChain != null && authzData.clientCertChain.length > 0) {
            toBeRenewed = authzData.clientCertChain[0];
        }

        if (toBeRenewed == null) {
            throw new ForbiddenException("Unable to locate certificate to be renewed.");
        }

        Object authzResult = getRequestAuthorizer().authorizeSimplereenroll(authzData, csr, toBeRenewed);

        X509Certificate cert = getBackend().simplereenroll(label, csr, authzData,  authzResult);
        return certResponse(cert);
    }

    private byte[] fullcmc(Optional<String> label, ESTRequestAuthorizationData authzData, byte[] data) throws PKIException {
        // For now, authorization is handled similarly to simpleenroll
        // TODO: implement proper CMC-specific authorization if needed
        Object authzResult = getRequestAuthorizer().authorizeFullCMC(authzData, data);

        return getBackend().fullcmc(label, data, authzData, authzResult);
    }

    private ESTRequestAuthorizationData makeAuthzData(Optional<String> label, HttpServletRequest servletRequest) {
        ESTRequestAuthorizationData data = new ESTRequestAuthorizationData();
        data.label = label;

        Principal principal = servletRequest.getUserPrincipal();
        if (principal == null) {
            // Not authenticated.  We shouldn't reach this case because the
            // container security constraint should handle authentication.
            throw new UnauthorizedException("Not authenticated");
        }
        logger.info("ESTFrontend: authenticated client: " + principal);
        data.principal = principal;

        // retreieve client certificate chain (if available)
        data.clientCertChain = (X509Certificate[])
            servletRequest.getAttribute(Globals.CERTIFICATES_ATTR);

        data.remoteAddr = servletRequest.getRemoteAddr();

        return data;
    }

    /** Parse a PKCS10 CSR
     */
    private static PKCS10 parseCSR(byte[] data) throws PKIException {
        try {
            // Base64.decodeBase64 ignores non-base64 bytes.
            // Decoding will not fail, but if the request body is
            // not valid base64, it won't decode to a valid CSR, so
            // CSR parsing will fail and we will still return 400.
            return new PKCS10(Base64.decodeBase64(data));
        } catch (
                IOException | IllegalArgumentException
                | SignatureException | NoSuchAlgorithmException e) {
            // something wrong with the request data, e.g.
            // malformed, invalid signature or unsupported algorithm
            //
            // IOException may arise due to failed DER decoding.
            throw new BadRequestException("Invalid CSR: " + e, e);
        } catch (Exception e) {
            // Other kinds of errors to be treated as server error
            throw new PKIException("Internal server error decoding CSR: "+ e, e);
        }
    }


    /** Build a response containing the issued certificate
     */
    private byte[] certResponse(X509Certificate cert) throws PKIException {
        // Build a CertificateChain with a single certificate.  This is a
        // convenient way to produce the certs-only CMC Simple PKI response
        // i.e. a PKCS #7 SignedData object with no signature and a single
        // certificate.
        CertificateChain chain = new CertificateChain(cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            chain.encode(out);
        } catch (IOException e) {
            logger.error("Error encoding certificate chain: " + e, e);
            throw new PKIException("Error encoding certificate chain: " + e, e);
        }
        return Base64.encodeBase64(out.toByteArray(), true /* wrap output */);
    }



    private byte[] cacerts(Optional<String> label) throws PKIException {
        CertificateChain chain = getBackend().cacerts(label);
        if (chain == null) {
            throw new ResourceNotFoundException(
                "Certificate chain for CA not available");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            chain.encode(out);
        } catch (IOException e) {
            throw new PKIException("Error encoding certificate chain", e);
        }

        return Base64.encodeBase64(out.toByteArray(), true /* wrap output */);
    }

    // shorthand convenience method
    private ESTBackend getBackend() {
        return ESTEngine.getInstance().getBackend();
    }


    // shorthand convenience method
    private ESTRequestAuthorizer getRequestAuthorizer() {
        return ESTEngine.getInstance().getRequestAuthorizer();
    }

    /**
     * Map CMC status to HTTP status code per RFC 7030/8951.
     *
     * CMC status values from RFC 5272:
     *   SUCCESS (0) - request was granted
     *   FAILED (2) - request was not granted
     *   PENDING (3) - request is being processed, poll back later
     *   NO_SUPPORT (4) - requested operation not supported
     *   CONFIRM_REQUIRED (5) - confirmation required before cert can be used
     *   POP_REQUIRED (6) - proof-of-possession required
     *   PARTIAL (7) - partial response, poll for unfulfilled portions
     *
     * @param cmcStatus CMC status value from CMCStatusInfoV2
     * @return HTTP status code
     */
    private int mapCMCStatusToHTTP(int cmcStatus) {
        // Simplified mapping for preliminary /fullcmc implementation.
        // This implementation focuses on agent-signed CMC requests which typically
        // complete immediately. RFC 5273 states "Servers MUST use the 200 response code
        // for successful responses" but doesn't define what to use for non-successful responses.
        switch (cmcStatus) {
            case 0: // SUCCESS
                // RFC 5273: "Servers MUST use the 200 response code for successful responses"
                return HttpServletResponse.SC_OK; // 200

            case 2: // FAILED
                // RFC 7030: "the server MUST specify either an HTTP 4xx error or
                // an HTTP 5xx error"
                return HttpServletResponse.SC_BAD_REQUEST; // 400

            case 4: // NO_SUPPORT
                // RFC 7030: "A client interprets an HTTP 404 or 501 response to
                // indicate that this service is not implemented"
                return HttpServletResponse.SC_NOT_IMPLEMENTED; // 501

            case 3: // PENDING
            case 5: // CONFIRM_REQUIRED
            case 6: // POP_REQUIRED
            case 7: // PARTIAL
                // These workflows are not yet implemented in this preliminary version.
                // Return 501 to clearly indicate lack of support.
                return HttpServletResponse.SC_NOT_IMPLEMENTED; // 501

            default:
                // Unknown CMC status - treat as server error
                logger.error("ESTServlet: Unknown CMC status: {}", cmcStatus);
                return HttpServletResponse.SC_INTERNAL_SERVER_ERROR; // 500
        }
    }
}
