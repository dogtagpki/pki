//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URI;
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
import org.dogtagpki.acme.validator.ACMEValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME challange.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeChallangeServlet",
        urlPatterns = "/chall/*")
public class ACMEChallengeServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEChallengeServlet.class);

    @WebAction(method = HttpMethod.POST, paths = { "{}"})
    public void authorization(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String challengeID = pathElement[0];
        logger.info("Validating challenge " + challengeID);

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

        ACMEAuthorization authorization = engine.getAuthorizationByChallenge(account, challengeID);

        String authzID = authorization.getID();

        ACMEChallenge challenge = authorization.getChallenge(challengeID);
        if (challenge == null) {
            // TODO: generate proper exception
            throw new Exception("Unknown challenge: " + challengeID);
        }

        String challengeStatus = challenge.getStatus();
        if (challengeStatus.equals("pending")) {

            String type = challenge.getType();
            logger.info("Challenge Type: " + type);

            ACMEValidator validator = engine.getValidator(type);
            if (validator == null) {
                // TODO: generate proper exception
                throw new Exception("Unsupported challenge type: " + type);
            }

            challenge.setStatus("processing");
            engine.updateAuthorization(account, authorization);

            ACMEChallengeProcessor processor = new ACMEChallengeProcessor(
                    account,
                    authorization,
                    challenge,
                    validator);

            // TODO: use thread pool
            new Thread(processor).start();

        } else if (challengeStatus.equals("processing")) {
            // TODO: retry the challenge

            // RFC 8555 Section 8.2: Retrying Challenges
            //
            // Clients can explicitly request a retry by re-sending their response
            // to a challenge in a new POST request (with a new nonce, etc.).  This
            // allows clients to request a retry when the state has changed (e.g.,
            // after firewall rules have been updated).  Servers SHOULD retry a
            // request immediately on receiving such a POST request.  In order to
            // avoid denial-of-service attacks via client-initiated retries, servers
            // SHOULD rate-limit such requests.

        } else if (challengeStatus.equals("valid")) {
                logger.info("Challenge is already valid");

        } else {
            // TODO: generate proper exception
            throw new Exception("Challenge is already " + challengeStatus);
        }
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();

        uriBuilder.setPath(request.getContextPath() + "/chall/" + challengeID);
        challenge.setURL(uriBuilder.build());


        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        uriBuilder.setPath(request.getContextPath() + "/authz/" + authzID);
        StringBuilder link = new StringBuilder("<")
                .append(uriBuilder.build().toString())
                .append(">;rel=\"up\"");

        response.addHeader("Link", link.toString());

        addIndex(request, response);

        PrintWriter out = response.getWriter();
        out.println(challenge.toJSON());
    }
}
