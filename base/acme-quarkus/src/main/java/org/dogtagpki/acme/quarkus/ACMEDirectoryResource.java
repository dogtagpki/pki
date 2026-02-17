//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.net.URL;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ACME directory endpoint (RFC 8555 Section 7.1.1).
 *
 * @author Endi S. Dewata (original)
 */
@Path("directory")
@ACMEProtocolEndpoint
public class ACMEDirectoryResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEDirectoryResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Context
    UriInfo uriInfo;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String getDirectory() throws Exception {
        logger.info("Creating directory");

        URL baseURL = engine.getBaseURL();
        String baseUri;
        if (baseURL != null) {
            baseUri = baseURL.toString();
            // Remove trailing slash if present
            if (baseUri.endsWith("/")) {
                baseUri = baseUri.substring(0, baseUri.length() - 1);
            }
        } else {
            baseUri = uriInfo.getBaseUri().toString();
            if (baseUri.endsWith("/")) {
                baseUri = baseUri.substring(0, baseUri.length() - 1);
            }
        }

        ACMEDirectory directory = new ACMEDirectory();
        directory.setMetadata(engine.getMetadata());

        directory.setNewNonce(new java.net.URI(baseUri + "/new-nonce"));
        directory.setNewAccount(new java.net.URI(baseUri + "/new-account"));
        directory.setNewOrder(new java.net.URI(baseUri + "/new-order"));
        directory.setRevokeCert(new java.net.URI(baseUri + "/revoke-cert"));

        logger.info("Directory:\n" + directory);
        return directory.toJSON();
    }
}
