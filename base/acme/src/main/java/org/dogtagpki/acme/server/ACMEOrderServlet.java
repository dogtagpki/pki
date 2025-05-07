//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
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

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME order.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeOrderServlet",
        urlPatterns = "/order/*")
public class ACMEOrderServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEOrderServlet.class);

    @WebAction(method = HttpMethod.POST, paths = { "{}"})
    public void order(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String orderID = pathElement[0];
        logger.info("Retrieving order " + orderID);

        String requestData = request.getReader().lines().collect(Collectors.joining());
        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
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

        ACMEOrder order = engine.getOrder(account, orderID);
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        String[] authzIDs = order.getAuthzIDs();
        if (authzIDs != null) {
            ArrayList<URI> authzURLs = new ArrayList<>();
            for (String authzID : authzIDs) {
                uriBuilder.setPath(request.getContextPath() + "/authz/" + authzID);
                authzURLs.add(uriBuilder.build());
            }
            order.setAuthorizations(authzURLs.toArray(new URI[authzURLs.size()]));
        }

        uriBuilder.setPath(request.getContextPath() + "/order/" + orderID + "/finalize");
        order.setFinalize(uriBuilder.build());

        String certID = order.getCertID();
        if (certID != null) {
            uriBuilder.setPath(request.getContextPath() + "/cert/" + certID);
            order.setCertificate(uriBuilder.build());
        }

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);
        PrintWriter out = response.getWriter();
        out.println(order.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = { "{}/finalize"})
    public void finalizeOrder(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String orderID = pathElement[0];
        logger.info("Finalizing order " + orderID);

        String requestData = request.getReader().lines().collect(Collectors.joining());
        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);

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


            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:orderNotReady");
            error.setDetail("Order not ready: " + orderID);

            throw new ACMEException(HttpServletResponse.SC_FORBIDDEN, error);
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

        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        uriBuilder.setPath(request.getContextPath() + "/order/" + orderID + "/finalize");
        order.setFinalize(uriBuilder.build());

        uriBuilder.setPath(request.getContextPath() + "/cert/" + certID);
        order.setCertificate(uriBuilder.build());

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        /* This is not required by ACME protocol but mod_md has a
         * bug[1] causing it to fail if there is no Location header
         * in the response.  So we add it.  This is also what
         * boulder / Let's Encrypt do.
         *
         * [1] https://github.com/icing/mod_md/issues/216
         */
        uriBuilder.setPath(request.getContextPath() + "/order/" + orderID);
        response.setHeader("Location", uriBuilder.build().toString());


        addIndex(request, response);
        PrintWriter out = response.getWriter();
        out.println(order.toJSON());
    }
}
