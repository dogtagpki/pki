//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEDirectory;

/**
 * @author Endi S. Dewata
 */
@Path("directory")
public class ACMEDirectoryService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEDirectoryService.class);

    @Context
    UriInfo uriInfo;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDirectory() throws Exception {

        logger.info("Creating directory");

        ACMEDirectory directory = new ACMEDirectory();

        ACMEEngine engine = ACMEEngine.getInstance();
        directory.setMetadata(engine.getMetadata());

        URI newNonceURL = uriInfo.getBaseUriBuilder().path("new-nonce").build();
        directory.setNewNonce(newNonceURL);

        URI newAccountURL = uriInfo.getBaseUriBuilder().path("new-account").build();
        directory.setNewAccount(newAccountURL);

        URI newOrderURL = uriInfo.getBaseUriBuilder().path("new-order").build();
        directory.setNewOrder(newOrderURL);

        URI revokeCertURL = uriInfo.getBaseUriBuilder().path("revoke-cert").build();
        directory.setRevokeCert(revokeCertURL);

        logger.info("Directory:\n" + directory);

        ResponseBuilder builder = Response.ok();
        builder.entity(directory);

        return builder.build();
    }
}
