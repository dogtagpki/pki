//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Locale;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.common.CAInfo;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JAX-RS resource for CA info operations.
 * Replaces CAInfoServlet.
 */
@Path("v2/info")
public class CAInfoResource {

    private static final Logger logger = LoggerFactory.getLogger(CAInfoResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getInfo() throws Exception {
        logger.debug("CAInfoResource.getInfo()");
        CAEngine engine = engineQuarkus.getEngine();
        CAInfo info = engine.getInfo(Locale.getDefault());
        return Response.ok(info.toJSON()).build();
    }
}
