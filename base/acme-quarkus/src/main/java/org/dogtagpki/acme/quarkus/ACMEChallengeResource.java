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
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.validator.ACMEValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME challenge endpoint (RFC 8555 Section 7.5.1).
 *
 * @author Endi S. Dewata (original)
 */
@Path("chall")
@ACMEProtocolEndpoint
public class ACMEChallengeResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEChallengeResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Path("{challengeID}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response respondToChallenge(@PathParam("challengeID") String challengeID, String requestData) throws Exception {

        logger.info("Validating challenge " + challengeID);

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        ACMEAuthorization authorization = engine.getAuthorizationByChallenge(account, challengeID);
        String authzID = authorization.getID();

        ACMEChallenge challenge = authorization.getChallenge(challengeID);
        if (challenge == null) {
            throw new Exception("Unknown challenge: " + challengeID);
        }

        String challengeStatus = challenge.getStatus();
        if (challengeStatus.equals("pending")) {

            String type = challenge.getType();
            logger.info("Challenge Type: " + type);

            ACMEValidator validator = engine.getValidator(type);
            if (validator == null) {
                throw new Exception("Unsupported challenge type: " + type);
            }

            challenge.setStatus("processing");
            engine.updateAuthorization(account, authorization);

            ACMEChallengeProcessorQuarkus processor = new ACMEChallengeProcessorQuarkus(
                    account,
                    authorization,
                    challenge,
                    validator);

            new Thread(processor).start();

        } else if (challengeStatus.equals("processing")) {
            // TODO: retry the challenge
        } else if (challengeStatus.equals("valid")) {
            logger.info("Challenge is already valid");
        } else {
            throw new Exception("Challenge is already " + challengeStatus);
        }

        String baseUri = getBaseUri();
        challenge.setURL(new URI(baseUri + "/chall/" + challengeID));

        ACMENonce nonce = engine.createNonce();

        Response.ResponseBuilder responseBuilder = Response.ok(challenge.toJSON())
                .header("Replay-Nonce", nonce.getID())
                .header("Link", "<" + baseUri + "/authz/" + authzID + ">;rel=\"up\"")
                .header("Link", getIndexLink());

        return responseBuilder.build();
    }

    private String getBaseUri() {
        String baseUri = uriInfo.getBaseUri().toString();
        if (baseUri.endsWith("/")) {
            baseUri = baseUri.substring(0, baseUri.length() - 1);
        }
        return baseUri;
    }

    private String getIndexLink() {
        return "<" + getBaseUri() + "/directory>;rel=\"index\"";
    }
}
