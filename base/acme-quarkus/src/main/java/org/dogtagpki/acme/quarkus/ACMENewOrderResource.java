//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.ValidationResult;
import org.dogtagpki.acme.server.ACMEIdentifierValidator;
import org.dogtagpki.acme.validator.ACMEValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME new order endpoint (RFC 8555 Section 7.4).
 *
 * @author Endi S. Dewata (original)
 */
@Path("new-order")
@ACMEProtocolEndpoint
public class ACMENewOrderResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMENewOrderResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createNewOrder(String requestData) throws Exception {

        logger.info("Creating new order");
        Date currentTime = new Date();

        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEOrder orderRequest = ACMEOrder.fromJSON(payload);
        ArrayList<String> authzIDs = new ArrayList<>();

        byte[] bytes = new byte[16];
        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        random.nextBytes(bytes);
        String token = Base64.encodeBase64URLSafeString(bytes);
        logger.info("Token: " + token);

        String baseUri = getBaseUri();

        logger.info("Generating authorization for each identifier");
        for (ACMEIdentifier identifier : orderRequest.getIdentifiers()) {

            String type = identifier.getType();
            String value = identifier.getValue();
            logger.info("Identifier " + type + ": " + value);

            ValidationResult r = ACMEIdentifierValidator.validateSyntax(identifier);
            if (!r.isOK()) {
                throw new ACMEException(400, r.getError());
            }
            engine.getPolicy().validateIdentifier(identifier);

            boolean wildcard;
            if ("dns".equals(type) && value.startsWith("*.")) {
                wildcard = true;
                value = value.substring(2);
            } else {
                wildcard = false;
            }

            identifier = new ACMEIdentifier();
            identifier.setType(type);
            identifier.setValue(value);

            String authzID = engine.randomAlphanumeric(10);
            logger.info("- authorization ID: " + authzID);

            ACMEAuthorization authorization = new ACMEAuthorization();
            authorization.setID(authzID);
            authorization.setCreationTime(currentTime);
            authorization.setIdentifier(identifier);
            authorization.setWildcard(wildcard);

            Collection<ACMEChallenge> challenges = new ArrayList<>();
            for (ACMEValidator validator : engine.getValidators()) {
                ACMEChallenge challenge = validator.createChallenge(authzID, token);
                logger.info("  - challenge ID: " + challenge.getID());
                challenges.add(challenge);
            }

            authorization.setChallenges(challenges);
            authorization.setStatus("pending");

            Date expirationTime = engine.getPolicy().getPendingAuthorizationExpirationTime(currentTime);
            authorization.setExpirationTime(expirationTime);

            engine.addAuthorization(account, authorization);
            authzIDs.add(authzID);
        }

        String orderID = engine.randomAlphanumeric(10);
        logger.info("Order ID: " + orderID);

        ACMEOrder order = new ACMEOrder();
        order.setID(orderID);
        order.setCreationTime(currentTime);
        order.setIdentifiers(orderRequest.getIdentifiers());
        order.setNotBefore(orderRequest.getNotBefore());
        order.setNotAfter(orderRequest.getNotAfter());
        order.setAuthzIDs(authzIDs.toArray(new String[authzIDs.size()]));
        order.setStatus("pending");

        Date expirationTime = engine.getPolicy().getPendingOrderExpirationTime(currentTime);
        order.setExpirationTime(expirationTime);

        engine.addOrder(account, order);

        ArrayList<URI> authzURLs = new ArrayList<>();
        for (String authzID : authzIDs) {
            authzURLs.add(new URI(baseUri + "/authz/" + authzID));
        }
        order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));

        order.setFinalize(new URI(baseUri + "/order/" + orderID + "/finalize"));

        ACMENonce nonce = engine.createNonce();

        return Response.status(201)
                .header("Location", baseUri + "/order/" + orderID)
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .entity(order.toJSON())
                .build();
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
