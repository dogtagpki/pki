//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.ws.rs.ServiceUnavailableException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.ext.Provider;

/**
 * @author Fraser Tweedale
 */
@Provider
@PreMatching  // run filter before JAX-RS request matching
public class ACMERequestFilter implements ContainerRequestFilter {

    public static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(ACMERequestFilter.class);

    @Override
    public void filter(ContainerRequestContext requestContext) {
        ACMEEngine engine = ACMEEngine.getInstance();
        if (!engine.isEnabled()) {
            throw new ServiceUnavailableException("ACME service is disabled");
        }
    }
}
