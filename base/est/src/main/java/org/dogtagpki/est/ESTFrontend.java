package org.dogtagpki.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Optional;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.codec.binary.Base64;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.PKIException;

/**
 * The EST API frontend.
 *
 * @author Fraser Tweedale
 */
@Path("")
public class ESTFrontend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTFrontend.class);

    // shorthand convenience method
    private ESTBackend getBackend() {
        return ESTEngine.getInstance().getBackend();
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

    private Response cacerts(Optional<String> label) {
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
    @Produces("application/pkcs7-mime")
    public Response simpleenroll(byte[] data) throws Throwable {
        logger.debug("ESTFrontend.simpleenroll: processing request");
        PKCS10 csr;
        try {
            // Base64.decodeBase64 ignores non-base64 bytes.
            // Decoding will not fail, but if the request body is
            // not valid base64, it won't decode to a valid CSR, so
            // CSR parsing will fail and we will still return 400.
            csr = new PKCS10(Base64.decodeBase64(data));
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

        // TODO authn, authz.
        // Define separate interface(s) for these, such that failures may result
        // in 401 or 403 response, without complicating the issuer backend interface.

        ESTEnrollResult result = getBackend().simpleenroll(Optional.empty(), csr);

        if (result.isSuccess()) {
            // Build a CertificateChain with a single certificate.  This is a
            // convenient way to produce the certs-only CMC Simple PKI response
            // i.e. a PKCS #7 SignedData object with no signature and a single
            // certificate.
            CertificateChain chain = new CertificateChain(result.getCertificate());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                chain.encode(out);
            } catch (IOException e) {
                throw new PKIException("Error encoding certificate chain", e);
            }
            return Response.ok(Base64.encodeBase64(out.toByteArray(), true /* wrap output */)).build();
        } else {
            throw result.getError();
        }
    }

    @POST
    @Path("{label}/simpleenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime")
    public Response simpleenroll(@PathParam("label") String label, String data) {
        ResponseBuilder builder = Response.ok();
        builder.entity("TODO we got the data for label <" + label + ">: " + data);
        return builder.build();
    }

    @POST
    @Path("simplereenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime")
    public Response simplereenroll(String data) {
        ResponseBuilder builder = Response.ok();
        builder.entity("TODO we got the data: " + data);
        return builder.build();
    }

    @POST
    @Path("{label}/simplereenroll")
    @Consumes("application/pkcs10")
    @Produces("application/pkcs7-mime")
    public Response simplereenroll(@PathParam("label") String label, String data) {
        ResponseBuilder builder = Response.ok();
        builder.entity("TODO we got the data for label <" + label + ">: " + data);
        return builder.build();
    }

}
