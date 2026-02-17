//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS Application class for ACME Quarkus.
 *
 * Sets the base path for all ACME REST endpoints.
 */
@ApplicationPath("/")
public class ACMEApplicationQuarkus extends Application {
}
