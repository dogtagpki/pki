//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URI;
import java.util.Collection;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME authorization.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeAuthorizationServlet",
        urlPatterns = "/authz/*")
public class ACMEAuthorizationServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEAuthorizationServlet.class);

    @WebAction(method = HttpMethod.POST, paths = { "{}"})
    public void authorization(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String authzID = pathElement[0];
        logger.info("Checking authorization " + authzID);

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

        ACMEAuthorization authorization = engine.getAuthorization(account, authzID);
        String authorizationStatus = authorization.getStatus();
        logger.info("Authorization status: " + authorizationStatus);

        Collection<ACMEChallenge> challenges = authorization.getChallenges();

        logger.info("Challenges:");
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        for (ACMEChallenge challenge : challenges) {
            logger.info("- " + challenge.getType() + ": " + challenge.getStatus());
            uriBuilder.setPath(request.getContextPath() + "/chall/" + challenge.getID());
            challenge.setURL(uriBuilder.build());
        }

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);

        PrintWriter out = response.getWriter();
        out.println(authorization.toJSON());
    }
}
