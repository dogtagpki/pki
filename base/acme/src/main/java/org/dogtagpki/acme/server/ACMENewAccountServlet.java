//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME new account.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeNewAccountServlet",
        urlPatterns = "/new-account/*")
public class ACMENewAccountServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMENewAccountServlet.class);

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void updateAccount(HttpServletRequest request, HttpServletResponse response) throws Exception {

        logger.info("Creating new account");
        Date currentTime = new Date();
        String requestData = request.getReader().lines().collect(Collectors.joining());
        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);
        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        JWK jwk = header.getJwk();
        logger.info("JWK: " + jwk);

        engine.validateJWS(jws, header.getAlg(), jwk);

        // generate account ID from JWK thumbprint
        String accountID = engine.generateThumbprint(jwk);
        logger.info("Account ID: " + accountID);

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);
        URIBuilder accountURL = new URIBuilder(request.getRequestURL().toString());
        accountURL.removeQuery();
        accountURL.setPath(request.getContextPath() + "/acct/" + accountID);
        response.setHeader("Location", accountURL.build().toString());

        ACMEAccount account = engine.getAccount(accountID, false);

        if (account == null) {

            account = ACMEAccount.fromJSON(payload);

            Boolean onlyReturnExisting = account.getOnlyReturnExisting();
            if (onlyReturnExisting != null && onlyReturnExisting) {
                throw engine.createAccountDoesNotExistException(accountID);
            }

            logger.info("Creating new account");

            Boolean termsOfServiceAgreed = account.getTermsOfServiceAgreed();
            if (termsOfServiceAgreed == null || !termsOfServiceAgreed) {
                // TODO: generate proper exception
                throw new Exception("Missing terms of service agreement");
            }

            account.setID(accountID);
            account.setCreationTime(currentTime);
            account.setJWK(jwk);
            account.setStatus("valid");

            engine.createAccount(account);

            response.setStatus(HttpServletResponse.SC_CREATED);
        } else {

            logger.info("Account already exists");

            engine.validateAccount(accountID, account);
        }

        // RFC 8555 Section 7.1.2.1 Orders List
        //
        // Each account object includes an "orders" URL from which a list of
        // orders created by the account can be fetched via POST-as-GET request.
        accountURL.setPath(accountURL.getPath() + "/orders");
        account.setOrders(accountURL.build());

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());
        addIndex(request, response);

        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }
}
