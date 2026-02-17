//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;

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
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME order endpoint (RFC 8555 Section 7.1.3 and 7.4).
 *
 * @author Endi S. Dewata (original)
 */
@Path("order")
@ACMEProtocolEndpoint
public class ACMEOrderResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEOrderResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @POST
    @Path("{orderID}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOrder(@PathParam("orderID") String orderID, String requestData) throws Exception {

        logger.info("Retrieving order " + orderID);

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

        ACMEOrder order = engine.getOrder(account, orderID);

        String baseUri = getBaseUri();

        String[] authzIDs = order.getAuthzIDs();
        if (authzIDs != null) {
            ArrayList<URI> authzURLs = new ArrayList<>();
            for (String authzID : authzIDs) {
                authzURLs.add(new URI(baseUri + "/authz/" + authzID));
            }
            order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));
        }

        order.setFinalize(new URI(baseUri + "/order/" + orderID + "/finalize"));

        String certID = order.getCertID();
        if (certID != null) {
            order.setCertificate(new URI(baseUri + "/cert/" + certID));
        }

        ACMENonce nonce = engine.createNonce();

        return Response.ok(order.toJSON())
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
                .build();
    }

    @POST
    @Path("{orderID}/finalize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response finalizeOrder(@PathParam("orderID") String orderID, String requestData) throws Exception {

        logger.info("Finalizing order " + orderID);

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

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEOrder order = engine.getOrder(account, orderID);

        if (!order.getStatus().equals("ready")) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:orderNotReady");
            error.setDetail("Order not ready: " + orderID);
            throw new ACMEException(403, error);
        }

        order.setStatus("processing");

        Date processingOrderExpirationTime = engine.getPolicy().getProcessingOrderExpirationTime(new Date());
        order.setExpirationTime(processingOrderExpirationTime);

        engine.updateOrder(account, order);

        ACMEOrder orderRequest = ACMEOrder.fromJSON(payload);

        String csr = orderRequest.getCSR();
        logger.info("CSR: " + csr);

        byte[] csrBytes = Utils.base64decode(csr);
        PKCS10 pkcs10 = new PKCS10(csrBytes);

        engine.validateCSR(account, order, pkcs10);

        ACMEIssuer issuer = engine.getIssuer();
        String certID = issuer.issueCertificate(pkcs10);
        logger.info("Certificate issued: " + certID);

        order.setCertID(certID);
        order.setStatus("valid");

        Date validOrderExpirationTime = engine.getPolicy().getValidOrderExpirationTime(new Date());
        order.setExpirationTime(validOrderExpirationTime);

        engine.updateOrder(account, order);

        String baseUri = getBaseUri();

        order.setFinalize(new URI(baseUri + "/order/" + orderID + "/finalize"));
        order.setCertificate(new URI(baseUri + "/cert/" + certID));

        ACMENonce nonce = engine.createNonce();

        return Response.ok(order.toJSON())
                .header("Location", baseUri + "/order/" + orderID)
                .header("Replay-Nonce", nonce.getID())
                .header("Link", getIndexLink())
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
