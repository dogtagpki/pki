//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.dogtagpki.acme.database.ACMEDatabase;

/**
 * @author Endi S. Dewata
 */
@Path("disable")
public class ACMEDisableService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEDisableService.class);

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST() throws Exception {

        logger.info("Disabling ACME services");

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase database = engine.getDatabase();
        database.setEnabled(false);

        ResponseBuilder builder = Response.ok();
        return builder.build();
    }
}
