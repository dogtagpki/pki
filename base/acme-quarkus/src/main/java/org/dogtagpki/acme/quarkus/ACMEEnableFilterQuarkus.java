//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import java.io.IOException;

import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.acme.database.ACMEDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Quarkus ContainerRequestFilter that checks if the ACME service is enabled.
 *
 * Replaces the Tomcat ACMEEnableFilter (HttpFilter). Applied to all ACME
 * protocol endpoints but not to admin endpoints (enable/disable/login/logout).
 *
 * @author Fraser Tweedale (original)
 */
@Provider
@ACMEProtocolEndpoint
public class ACMEEnableFilterQuarkus implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(ACMEEnableFilterQuarkus.class);

    @Inject
    ACMEEngineQuarkus engine;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        ACMEDatabase database = engine.getDatabase();

        Boolean enabled = null;
        try {
            enabled = database.getEnabled();
        } catch (Exception e) {
            throw new IOException("Unable to access ACME database: " + e.getMessage(), e);
        }

        if (enabled == null) {
            enabled = engine.isEnabled();
        }

        if (!enabled) {
            logger.info("ACMEEnableFilter: ACME service is disabled");
            requestContext.abortWith(
                Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("ACME service is disabled")
                    .build()
            );
        }
    }
}
