//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.utils.URIBuilder;
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
import org.dogtagpki.acme.validator.ACMEValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME new order.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeNewOrderServlet",
        urlPatterns = "/new-order/*")
public class ACMENewOrderServlet extends ACMEServlet {


    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMENewOrderServlet.class);

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void createNewOrder(HttpServletRequest request, HttpServletResponse response) throws Exception {

        logger.info("Creating new order");
        Date currentTime = new Date();
        String requestData = request.getReader().lines().collect(Collectors.joining());
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

        // generate 128-bit token for authorization challenges
        // TODO: make it configurable

        byte[] bytes = new byte[16];
        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
        random.nextBytes(bytes);
        String token = Base64.encodeBase64URLSafeString(bytes);
        logger.info("Token: " + token);

        logger.info("Generating authorization for each identifiers");
        for (ACMEIdentifier identifier : orderRequest.getIdentifiers()) {

            String type = identifier.getType();
            String value = identifier.getValue();
            logger.info("Identifier " + type + ": " + value);

            ValidationResult r = ACMEIdentifierValidator.validateSyntax(identifier);
            if (!r.isOK()) {
                throw new ACMEException(HttpServletResponse.SC_BAD_REQUEST, r.getError());
            }
            engine.getPolicy().validateIdentifier(identifier);

            // RFC 8555 Section 7.1.3: Order Objects
            //
            // Any identifier of type "dns" in a newOrder request MAY have a
            // wildcard domain name as its value.  A wildcard domain name consists
            // of a single asterisk character followed by a single full stop
            // character ("*.") followed by a domain name as defined for use in the
            // Subject Alternate Name Extension by [RFC5280].  An authorization
            // returned by the server for a wildcard domain name identifier MUST NOT
            // include the asterisk and full stop ("*.") prefix in the authorization
            // identifier value.  The returned authorization MUST include the
            // optional "wildcard" field, with a value of true.

            boolean wildcard;
            if ("dns".equals(type) && value.startsWith("*.")) {
                wildcard = true;
                value = value.substring(2); // remove *. prefix
            } else {
                wildcard = false;
            }

            // store identifier for authorization without *. prefix
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

        // RFC 8555 Section 7.1.3: Order Objects
        //
        // expires (optional, string):  The timestamp after which the server
        //    will consider this order invalid, encoded in the format specified
        //    in [RFC3339].  This field is REQUIRED for objects with "pending"
        //    or "valid" in the status field.

        order.setStatus("pending");

        Date expirationTime = engine.getPolicy().getPendingOrderExpirationTime(currentTime);
        order.setExpirationTime(expirationTime);

        engine.addOrder(account, order);
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        ArrayList<URI> authzURLs = new ArrayList<>();
        for (String authzID : authzIDs) {
            uriBuilder.setPath(request.getContextPath() + "/authz/" + authzID);
            authzURLs.add(uriBuilder.build());
        }
        order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));

        uriBuilder.setPath(request.getContextPath() + "/order/" + orderID + "/finalize");
        order.setFinalize(uriBuilder.build());

        uriBuilder.setPath(request.getContextPath() + "/order/" + orderID);
        response.setHeader("Location", uriBuilder.build().toString());
        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);

        response.setStatus(HttpServletResponse.SC_CREATED);
        PrintWriter out = response.getWriter();
        out.println(order.toJSON());
    }
}
