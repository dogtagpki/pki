//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS Application for TKS Quarkus deployment.
 * Endpoint resources are auto-discovered by Quarkus CDI.
 */
@ApplicationPath("/")
public class TKSApplicationQuarkus extends Application {
}
