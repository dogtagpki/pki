//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.FeatureServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caFeature",
        urlPatterns = "/v2/config/features/*")
public class CAFeatureServlet extends FeatureServlet {
    private static final long serialVersionUID = 1L;
}
