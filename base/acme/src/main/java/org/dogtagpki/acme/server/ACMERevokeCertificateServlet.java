//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * ACME revoke certificate.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeRevokeCertificateServlet",
        urlPatterns = "/revoke-cert/*")
public class ACMERevokeCertificateServlet extends ACMEServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMERevokeCertificateServlet.class);

    @WebAction(method = HttpMethod.POST, paths = { ""})
    public void revoke(HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("Revoking certificate");
        String requestData = request.getReader().lines().collect(Collectors.joining());
        JWS jws = JSONSerializer.fromJSON(requestData, JWS.class);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMERevocation revocation = ACMERevocation.fromJSON(payload);
        URI kid = header.getKid();
        JWK jwk = header.getJwk();

        // RFC 8555 Section 6.2: Request Authentication
        //
        // The "jwk" and "kid" fields are mutually exclusive.  Servers MUST
        // reject requests that contain both.
        //
        // For newAccount requests, and for revokeCert requests authenticated by
        // a certificate key, there MUST be a "jwk" field.  This field MUST
        // contain the public key corresponding to the private key used to sign
        // the JWS.
        //
        // For all other requests, the request is signed using an existing
        // account, and there MUST be a "kid" field.  This field MUST contain
        // the account URL received by POSTing to the newAccount resource.

        if (kid != null && jwk == null) {

            String kidPath = kid.getPath();
            String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
            logger.info("Account ID: " + accountID);

            // validate that the revocation request was signed with the account key
            ACMEAccount account = engine.getAccount(accountID);
            engine.validateJWS(jws, header.getAlg(), account.getJWK());

            // validate that the account is authorized to revoke the cert
            engine.validateRevocation(account, revocation);

        } else if (kid == null && jwk != null) {
            // validate that the revocation request was signed
            // with the key of the cert being revoked
            engine.validateJWS(jws, header.getAlg(), jwk);

        } else {
            // TODO: generate proper exception
            throw new Exception("Invalid revocation request");
        }

        ACMEIssuer issuer = engine.getIssuer();
        issuer.revokeCertificate(revocation);

        logger.info("Certificate revoked");

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());

        addIndex(request, response);
    }
}
