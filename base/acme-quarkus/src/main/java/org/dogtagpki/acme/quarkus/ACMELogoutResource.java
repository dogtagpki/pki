//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ACME logout endpoint.
 *
 * In Quarkus (stateless), session invalidation is a no-op.
 * This endpoint exists for API compatibility with the Tomcat version.
 */
@Path("logout")
public class ACMELogoutResource {

    private static final Logger logger = LoggerFactory.getLogger(ACMELogoutResource.class);

    @POST
    public Response logout() {
        logger.info("ACMELogoutResource: Logout requested (stateless - no-op)");
        return Response.noContent().build();
    }
}
