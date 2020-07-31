//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.Path;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMENonce;

/**
 * @author Endi S. Dewata
 */
@Path("new-nonce")
public class ACMENewNonceService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMENewNonceService.class);

    @Context
    UriInfo uriInfo;

    @HEAD
    public Response headNewNonce() throws Exception {
        ResponseBuilder builder = Response.ok();
        createNonce(builder);
        return builder.build();
    }

    @GET
    public Response getNewNonce() throws Exception {
        ResponseBuilder builder = Response.noContent();
        createNonce(builder);
        return builder.build();
    }

    public void createNonce(ResponseBuilder builder) throws Exception {

        logger.info("Creating nonce");

        ACMEEngine engine = ACMEEngine.getInstance();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        CacheControl cc = new CacheControl();
        cc.setNoStore(true);
        builder.cacheControl(cc);

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");
    }
}
