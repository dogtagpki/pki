//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.acme.database.ACMEDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ACME administrative endpoints for enabling/disabling the service.
 *
 * @author Endi S. Dewata (original)
 */
@Path("")
public class ACMEAdminResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMEAdminResource.class);

    @Inject
    ACMEEngineQuarkus engine;

    @POST
    @Path("enable")
    @RolesAllowed({"Administrators", "Enterprise ACME Administrators"})
    public Response enable() throws Exception {
        logger.info("Enabling ACME services");

        ACMEDatabase database = engine.getDatabase();
        database.setEnabled(true);

        return Response.noContent().build();
    }

    @POST
    @Path("disable")
    @RolesAllowed({"Administrators", "Enterprise ACME Administrators"})
    public Response disable() throws Exception {
        logger.info("Disabling ACME services");

        ACMEDatabase database = engine.getDatabase();
        database.setEnabled(false);

        return Response.noContent().build();
    }
}
