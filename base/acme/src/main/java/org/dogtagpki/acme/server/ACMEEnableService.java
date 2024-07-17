//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

import org.dogtagpki.acme.database.ACMEDatabase;

/**
 * @author Endi S. Dewata
 */
@Path("enable")
public class ACMEEnableService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEnableService.class);

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST() throws Exception {

        logger.info("Enabling ACME services");

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase database = engine.getDatabase();
        database.setEnabled(true);

        ResponseBuilder builder = Response.ok();
        return builder.build();
    }
}
