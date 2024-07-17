//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.net.URL;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEDirectory;

/**
 * @author Endi S. Dewata
 */
@Path("directory")
@ACMEManagedService
public class ACMEDirectoryService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEDirectoryService.class);

    @Context
    UriInfo uriInfo;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDirectory() throws Exception {

        logger.info("Creating directory");

        ACMEEngine engine = ACMEEngine.getInstance();
        URL baseURL = engine.getBaseURL();

        UriBuilder uriBuilder;
        if (baseURL != null) {
            uriBuilder = UriBuilder.fromUri(baseURL.toURI());
        } else {
            uriBuilder = uriInfo.getBaseUriBuilder();
        }

        ACMEDirectory directory = new ACMEDirectory();

        directory.setMetadata(engine.getMetadata());

        URI newNonceURL = uriBuilder.clone().path("new-nonce").build();
        directory.setNewNonce(newNonceURL);

        URI newAccountURL = uriBuilder.clone().path("new-account").build();
        directory.setNewAccount(newAccountURL);

        URI newOrderURL = uriBuilder.clone().path("new-order").build();
        directory.setNewOrder(newOrderURL);

        URI revokeCertURL = uriBuilder.clone().path("revoke-cert").build();
        directory.setRevokeCert(revokeCertURL);

        logger.info("Directory:\n" + directory);

        ResponseBuilder builder = Response.ok();
        builder.entity(directory);

        return builder.build();
    }
}
