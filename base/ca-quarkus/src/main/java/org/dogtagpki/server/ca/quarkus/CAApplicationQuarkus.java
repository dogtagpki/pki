//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.ApplicationPath;

/**
 * JAX-RS Application for CA Quarkus deployment.
 */
@ApplicationPath("/")
public class CAApplicationQuarkus extends Application {
}
