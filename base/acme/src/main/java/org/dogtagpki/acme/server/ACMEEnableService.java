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
        engine.setEnabled(true);

        ResponseBuilder builder = Response.ok();
        return builder.build();
    }
}
