//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;

/**
 * @author Endi S. Dewata
 */
@Path("revoke-cert")
public class ACMERevokeCertificateService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMERevokeCertificateService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCert(JWS jws) throws Exception {

        logger.info("Revoking certificate");

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMERevocation revocation = ACMERevocation.fromJSON(payload);
        URI kid = header.getKid();
        JWK jwk = header.getJwk();

        // RFC 8555 Section 6.2: Request Authentication
        //
        // The "jwk" and "kid" fields are mutually exclusive.  Servers MUST
        // reject requests that contain both.
        //
        // For newAccount requests, and for revokeCert requests authenticated by
        // a certificate key, there MUST be a "jwk" field.  This field MUST
        // contain the public key corresponding to the private key used to sign
        // the JWS.
        //
        // For all other requests, the request is signed using an existing
        // account, and there MUST be a "kid" field.  This field MUST contain
        // the account URL received by POSTing to the newAccount resource.

        if (kid != null && jwk == null) {

            String kidPath = kid.getPath();
            String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
            logger.info("Account ID: " + accountID);

            // validate that the revocation request was signed with the account key
            ACMEAccount account = engine.getAccount(accountID);
            engine.validateJWS(jws, header.getAlg(), account.getJWK());

            // validate that the account is authorized to revoke the cert
            engine.validateRevocation(account, revocation);

        } else if (kid == null && jwk != null) {
            // validate that the revocation request was signed
            // with the key of the cert being revoked
            engine.validateJWS(jws, header.getAlg(), jwk);

        } else {
            // TODO: generate proper exception
            throw new Exception("Invalid revocation request");
        }

        ACMEIssuer issuer = engine.getIssuer();
        issuer.revokeCertificate(revocation);

        logger.info("Certificate revoked");

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        return builder.build();
    }
}
