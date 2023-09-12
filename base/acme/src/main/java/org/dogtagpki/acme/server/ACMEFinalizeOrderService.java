//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.Date;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;

/**
 * @author Endi S. Dewata
 */
@Path("order/{id}/finalize")
@ACMEManagedService
public class ACMEFinalizeOrderService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEFinalizeOrderService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String orderID, JWS jws) throws Exception {

        logger.info("Finalizing order " + orderID);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
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

            // RFC 8555 Section 7.4: Applying for Certificate Issuance
            //
            // A request to finalize an order will result in error if the order is
            // not in the "ready" state.  In such cases, the server MUST return a
            // 403 (Forbidden) error with a problem document of type
            // "orderNotReady".  The client should then send a POST-as-GET request
            // to the order resource to obtain its current state.  The status of the
            // order will indicate what action the client should take (see below).

            ResponseBuilder builder = Response.status(Response.Status.FORBIDDEN);
            builder.type("application/problem+json");

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:orderNotReady");
            error.setDetail("Order not ready: " + orderID);
            builder.entity(error);

            throw new WebApplicationException(builder.build());
        }

        order.setStatus("processing");

        Date processingOrderExpirationTime = engine.getPolicy().getProcessingOrderExpirationTime(new Date());
        order.setExpirationTime(processingOrderExpirationTime);

        engine.updateOrder(account, order);

        ACMEOrder request = ACMEOrder.fromJSON(payload);

        String csr = request.getCSR();
        logger.info("CSR: " + csr);

        byte[] csrBytes = Utils.base64decode(csr);
        PKCS10 pkcs10 = new PKCS10(csrBytes);

        engine.validateCSR(account, order, pkcs10);

        ACMEIssuer issuer = engine.getIssuer();
        String certID = issuer.issueCertificate(pkcs10);
        logger.info("Certificate issued: " + certID);

        order.setCertID(certID);

        // RFC 8555 Section 7.1.3: Order Objects
        //
        // expires (optional, string):  The timestamp after which the server
        //    will consider this order invalid, encoded in the format specified
        //    in [RFC3339].  This field is REQUIRED for objects with "pending"
        //    or "valid" in the status field.

        order.setStatus("valid");

        Date validOrderExpirationTime = engine.getPolicy().getValidOrderExpirationTime(new Date());
        order.setExpirationTime(validOrderExpirationTime);

        engine.updateOrder(account, order);

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

        URI certURL = uriInfo.getBaseUriBuilder().path("cert").path(certID).build();
        order.setCertificate(certURL);

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        /* This is not required by ACME protocol but mod_md has a
         * bug[1] causing it to fail if there is no Location header
         * in the response.  So we add it.  This is also what
         * boulder / Let's Encrypt do.
         *
         * [1] https://github.com/icing/mod_md/issues/216
         */
        URI orderURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).build();
        builder.location(orderURL);

        URI indexURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(indexURL, "index");

        builder.entity(order);

        return builder.build();
    }
}
