//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URI;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME certificate revocation endpoint (RFC 8555 Section 7.6).
 *
 * @author Endi S. Dewata (original)
 */
@Path("revoke-cert")
@ACMEProtocolEndpoint
public class ACMERevocationResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMERevocationResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response revoke(String requestData) throws Exception {

        logger.info("Revoking certificate");

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMERevocation revocation = ACMERevocation.fromJSON(payload);
        URI kid = header.getKid();
        JWK jwk = header.getJwk();

        if (kid != null && jwk == null) {

            String kidPath = kid.getPath();
            String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
            logger.info("Account ID: " + accountID);

            ACMEAccount account = engine.getAccount(accountID);
            engine.validateJWS(jws, header.getAlg(), account.getJWK());

            engine.validateRevocation(account, revocation);

        } else if (kid == null && jwk != null) {
            engine.validateJWS(jws, header.getAlg(), jwk);

        } else {
            throw new Exception("Invalid revocation request");
        }

        ACMEIssuer issuer = engine.getIssuer();
        issuer.revokeCertificate(revocation);

        logger.info("Certificate revoked");

        ACMENonce nonce = engine.createNonce();

        return Response.ok()
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .build();
    }

    private String getIndexLink() {
        String baseUri = uriInfo.getBaseUri().toString();
        if (baseUri.endsWith("/")) {
            baseUri = baseUri.substring(0, baseUri.length() - 1);
        }
        return "<" + baseUri + "/directory>;rel=\"index\"";
    }
}
