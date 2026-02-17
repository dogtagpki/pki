package org.dogtagpki.est.quarkus;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.base.UnsupportedMediaType;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cmsutil.crypto.CryptoUtil;

import org.dogtagpki.est.ESTBackend;
import org.dogtagpki.est.ESTRequestAuthorizer;
import org.dogtagpki.est.ESTRequestAuthorizationData;

import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.core.http.HttpServerRequest;

/**
 * EST API Frontend for Quarkus.
 *
 * Implements the EST protocol endpoints (RFC 7030) using Quarkus
 * JAX-RS with real PKI backend classes from pki-est.
 *
 * @author Fraser Tweedale (original)
 */
@Path("")
public class ESTFrontendQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(ESTFrontendQuarkus.class);

    @Inject
    ESTEngineQuarkus engine;

    @Context
    SecurityContext securityContext;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    HttpServerRequest httpRequest;

    private ESTBackend getBackend() {
        return engine.getBackend();
    }

    private ESTRequestAuthorizer getRequestAuthorizer() {
        return engine.getRequestAuthorizer();
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

        return Response.ok(Base64.encodeBase64(out.toByteArray(), true)).build();
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
        logger.debug("ESTFrontend.simpleenroll: processing request (label: {})", label);
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
        logger.debug("ESTFrontend.simplereenroll: processing request (label: {})", label);
        return reenroll(Optional.of(label), data);
    }

    @POST
    @Path("fullcmc")
    @Consumes("application/pkcs7-mime")
    @Produces("application/pkcs7-mime; smime-type=CMC-response")
    public Response fullcmc(byte[] data) {
        logger.debug("ESTFrontend.fullcmc: processing request (no label)");
        return handleFullCMC(Optional.empty(), data);
    }

    @POST
    @Path("{label}/fullcmc")
    @Consumes("application/pkcs7-mime")
    @Produces("application/pkcs7-mime; smime-type=CMC-response")
    public Response fullcmc(@PathParam("label") String label, byte[] data) {
        logger.debug("ESTFrontend.fullcmc: processing request (label: {})", label);
        return handleFullCMC(Optional.of(label), data);
    }

    private Response enroll(Optional<String> label, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);
        ESTRequestAuthorizationData authzData = makeAuthzData(label);

        Object authzResult = getRequestAuthorizer().authorizeSimpleenroll(authzData, csr);

        X509Certificate cert = getBackend().simpleenroll(label, csr, authzData, authzResult);
        return certResponse(cert);
    }

    private Response reenroll(Optional<String> label, byte[] data) throws PKIException {
        PKCS10 csr = parseCSR(data);
        ESTRequestAuthorizationData authzData = makeAuthzData(label);

        X509Certificate toBeRenewed = null;
        if (authzData.clientCertChain != null && authzData.clientCertChain.length > 0) {
            toBeRenewed = authzData.clientCertChain[0];
        }

        if (toBeRenewed == null) {
            throw new ForbiddenException("Unable to locate certificate to be renewed.");
        }

        ensureCSRMatchesToBeRenewedCert(csr, toBeRenewed);

        Object authzResult = getRequestAuthorizer().authorizeSimplereenroll(authzData, csr, toBeRenewed);

        X509Certificate cert = getBackend().simplereenroll(label, csr, authzData, authzResult);
        return certResponse(cert);
    }

    private Response handleFullCMC(Optional<String> label, byte[] data) throws PKIException {
        ESTRequestAuthorizationData authzData = makeAuthzData(label);

        Object authzResult = getRequestAuthorizer().authorizeFullCMC(authzData, data);

        byte[] cmcResponse = getBackend().fullcmc(label, data, authzData, authzResult);

        Integer cmcStatus = getBackend().getLastCMCStatus();
        if (cmcStatus == null) {
            throw new PKIException("CMC status not available from backend");
        }
        int httpStatus = mapCMCStatusToHTTP(cmcStatus);
        logger.debug("ESTFrontend.fullcmc: CMC status {} mapped to HTTP {}", cmcStatus, httpStatus);

        return Response.status(httpStatus)
                .entity(Base64.encodeBase64(cmcResponse, true))
                .build();
    }

    private ESTRequestAuthorizationData makeAuthzData(Optional<String> label) {
        ESTRequestAuthorizationData data = new ESTRequestAuthorizationData();
        data.label = label;

        Principal principal = securityContext.getUserPrincipal();
        if (principal == null) {
            throw new UnauthorizedException("Not authenticated");
        }
        logger.info("ESTFrontend: authenticated client: {}", principal);
        data.principal = principal;

        data.clientCertChain = getClientCertificates();
        data.remoteAddr = httpRequest.remoteAddress().hostAddress();

        return data;
    }

    private X509Certificate[] getClientCertificates() {
        try {
            javax.net.ssl.SSLSession sslSession = httpRequest.sslSession();
            if (sslSession != null) {
                java.security.cert.Certificate[] certs = sslSession.getPeerCertificates();
                if (certs != null && certs.length > 0) {
                    X509Certificate[] x509Certs = new X509Certificate[certs.length];
                    for (int i = 0; i < certs.length; i++) {
                        if (certs[i] instanceof X509Certificate) {
                            x509Certs[i] = (X509Certificate) certs[i];
                        }
                    }
                    return x509Certs;
                }
            }
        } catch (Exception e) {
            logger.debug("No client certificates available: {}", e.getMessage());
        }
        return null;
    }

    private static PKCS10 parseCSR(byte[] data) throws PKIException {
        try {
            return new PKCS10(Base64.decodeBase64(data));
        } catch (
                IOException | IllegalArgumentException
                | SignatureException | NoSuchAlgorithmException e) {
            throw new BadRequestException("Invalid CSR: " + e, e);
        } catch (Exception e) {
            throw new PKIException("Internal server error decoding CSR: "+ e, e);
        }
    }

    public static void ensureCSRMatchesToBeRenewedCert(PKCS10 csr, X509Certificate cert_)
            throws ForbiddenException {
        X509CertImpl cert;
        if (cert_ instanceof X509CertImpl) {
            cert = (X509CertImpl) cert_;
        } else {
            try {
                cert = new X509CertImpl(cert_.getEncoded());
            } catch (CertificateException e) {
                throw new ForbiddenException("Failed to decode certificate to be renewed.");
            }
        }

        if (!csr.getSubjectName().equals(cert.getSubjectName())) {
            throw new ForbiddenException("CSR subject does not match certificate to be renewed.");
        }

        SubjectAlternativeNameExtension csrSAN = null;
        try {
            csrSAN = (SubjectAlternativeNameExtension)
                CryptoUtil.getExtensionFromPKCS10(csr, SubjectAlternativeNameExtension.NAME);
        } catch (IOException | CertificateException e) {
            throw new BadRequestException("Failed to decode SAN extension in CSR");
        }

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
        }
    }

    private static Response certResponse(X509Certificate cert) throws PKIException {
        CertificateChain chain = new CertificateChain(cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            chain.encode(out);
        } catch (IOException e) {
            throw new PKIException("Error encoding certificate chain: " + e, e);
        }
        return Response.ok(Base64.encodeBase64(out.toByteArray(), true)).build();
    }

    /**
     * Map CMC status to HTTP status code per RFC 7030/8951.
     */
    private int mapCMCStatusToHTTP(int cmcStatus) {
        switch (cmcStatus) {
            case 0: // SUCCESS
                return 200;
            case 2: // FAILED
                return 400;
            case 4: // NO_SUPPORT
                return 501;
            case 3: // PENDING
            case 5: // CONFIRM_REQUIRED
            case 6: // POP_REQUIRED
            case 7: // PARTIAL
                return 501;
            default:
                logger.error("ESTFrontend: Unknown CMC status: {}", cmcStatus);
                return 500;
        }
    }
}
