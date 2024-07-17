package org.dogtagpki.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

import org.apache.catalina.Globals;
import org.apache.commons.codec.binary.Base64;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * The EST API frontend.
 *
 * @author Fraser Tweedale
 */
@Path("")
public class ESTFrontend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTFrontend.class);

    @Context
    protected HttpServletRequest servletRequest;

    // shorthand convenience method
    private ESTBackend getBackend() {
        return ESTEngine.getInstance().getBackend();
    }

    // shorthand convenience method
    private ESTRequestAuthorizer getRequestAuthorizer() {
        return ESTEngine.getInstance().getRequestAuthorizer();
    }

    @GET
    @Path("cacerts")
    @Produces("application/pkcs7-mime")
    public Response cacerts() {
        return cacerts(Optional.empty());
    }

    @GET
    @Path("{label}/cacerts")
    @Produces("application/pkcs7-mime")
    public Response cacerts(@PathParam("label") String label) {
        return cacerts(Optional.of(label));
    }

    private Response cacerts(Optional<String> label) throws PKIException {
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

        return Response.ok(Base64.encodeBase64(out.toByteArray(), true /* wrap output */)).build();
    }

    @POST
    @Path("simpleenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime; smime-type=certs-only")
    public Response simpleenroll(byte[] data) throws PKIException {
        logger.debug("ESTFrontend.simpleenroll: processing request (no label)");
        return enroll(Optional.empty(), data);
    }

    @POST
    @Path("{label}/simpleenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime; smime-type=certs-only")
    public Response simpleenroll(@PathParam("label") String label, byte[] data) {
        logger.debug("ESTFrontend.simpleenroll: processing request (label: " + label + ")");
        return enroll(Optional.of(label), data);
    }

    @POST
    @Path("simplereenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime; smime-type=certs-only")
    public Response simplereenroll(byte[] data) {
        logger.debug("ESTFrontend.simplereenroll: processing request (no label)");
        return reenroll(Optional.empty(), data);
    }

    @POST
    @Path("{label}/simplereenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime; smime-type=certs-only")
    public Response simplereenroll(@PathParam("label") String label, byte[] data) {
        logger.debug("ESTFrontend.simplereenroll: processing request (label: " + label + ")");
        return reenroll(Optional.of(label), data);
    }

    private Response enroll(Optional<String> label, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);

        Object authzResult = getRequestAuthorizer().authorizeSimpleenroll(makeAuthzData(label), csr);

        X509Certificate cert = getBackend().simpleenroll(label, csr, authzResult);
        return certResponse(cert);
    }

    private Response reenroll(Optional<String> label, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);

        ESTRequestAuthorizationData authzData = makeAuthzData(label);

        // TODO implement interface for retrieval of to-be-renewed cert.
        // For now, we unconditionally use the client certificate (if available).
        X509Certificate toBeRenewed = null;
        if (authzData.clientCertChain != null && authzData.clientCertChain.length > 0) {
            toBeRenewed = authzData.clientCertChain[0];
        }

        if (toBeRenewed == null) {
            throw new ForbiddenException("Unable to locate certificate to be renewed.");
        }

        ensureCSRMatchesToBeRenewedCert(csr, toBeRenewed);

        Object authzResult = getRequestAuthorizer().authorizeSimplereenroll(authzData, csr, toBeRenewed);

        X509Certificate cert = getBackend().simplereenroll(label, csr, authzResult);
        return certResponse(cert);
    }

    private ESTRequestAuthorizationData makeAuthzData(Optional<String> label) {
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

    /** Ensure subject info in CSR matches the certificate.
     *
     * https://www.rfc-editor.org/rfc/rfc7030#section-4.2.2 states:
     *
     *    The request Subject field and SubjectAltName extension MUST be
     *    identical to the corresponding fields in the certificate being
     *    renewed/rekeyed.
     *
     * This function implements that requirement.
     *
     * @throws ForbiddenException if fields are not identical.
     */
    public static void ensureCSRMatchesToBeRenewedCert(PKCS10 csr, X509Certificate cert_)
            throws ForbiddenException {
        // use a JSS X509CertImpl for easier access to the inner parts
        X509CertImpl cert;
        if (cert_ instanceof X509CertImpl) {
            cert = (X509CertImpl) cert_;
        } else {
            // construct X509CertImpl
            try {
                cert = new X509CertImpl(cert_.getEncoded());
            } catch (CertificateException e) {
                throw new ForbiddenException("Failed to decode certificate to be renewed.");
            }
        }

        // Compare Subject DNs.
        //
        // This comparison does not perform StringPrep or caseIgnoreMatch.
        // However, RFC 7030 says the values must be "identical", not "equal"
        // or "equivalent", so this seems reasonable.
        //
        if (!csr.getSubjectName().equals(cert.getSubjectName())) {
            throw new ForbiddenException("CSR subject does not match certificate to be renewed.");
        }

        // Compare SAN
        SubjectAlternativeNameExtension csrSAN = null;
        try {
            csrSAN = (SubjectAlternativeNameExtension)
                CryptoUtil.getExtensionFromPKCS10(csr, SubjectAlternativeNameExtension.NAME);
        } catch (IOException | CertificateException e) {
            throw new BadRequestException("Failed to decode SAN extension in CSR");
        }

        // TODO get SAN from t-b-r cert; compare
        SubjectAlternativeNameExtension certSAN = (SubjectAlternativeNameExtension)
            cert.getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString());

        if (csrSAN != null && certSAN != null) {
            if (!Arrays.equals(csrSAN.getExtensionValue(), certSAN.getExtensionValue())) {
                throw new ForbiddenException(
                    "SAN extensions of certificate to be renewed and CSR are not identical.");
            }
        } else if (csrSAN == null && certSAN != null) {
            throw new ForbiddenException(
                "Certificate to be renewed has SubjectAlternativeName extension, "
                + "but CSR does not."
            );
        } else if (csrSAN != null && certSAN == null) {
            throw new ForbiddenException(
                "Certificate to be renewed does not have SubjectAlternativeName extension, "
                + "but CSR does."
            );
        } // else both null, which is valid
    }

    /** Build a response containing the issued certificate
     */
    private static Response certResponse(X509Certificate cert) throws PKIException {
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
        return Response.ok(Base64.encodeBase64(out.toByteArray(), true /* wrap output */)).build();
    }

}
