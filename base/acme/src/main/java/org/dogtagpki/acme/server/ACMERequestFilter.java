//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.IOException;

import javax.ws.rs.ServiceUnavailableException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;

import org.dogtagpki.acme.database.ACMEDatabase;

/**
 * @author Fraser Tweedale
 */
@Provider
@ACMEManagedService
public class ACMERequestFilter implements ContainerRequestFilter {

    public static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(ACMERequestFilter.class);

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase database = engine.getDatabase();

        Boolean enabled = null;
        try {
            // get config property from database
            enabled = database.getEnabled();
        } catch (Exception e) {
            throw new IOException("Unable to access ACME database: " + e.getMessage(), e);
        }

        if (enabled == null) {
            // config property is unset in database, get it from config file instead
            enabled = engine.isEnabled();
        }

        if (!enabled) {
            logger.info("ACMERequestFilter: ACME service is disabled");
            throw new ServiceUnavailableException("ACME service is disabled");
        }
    }
}
