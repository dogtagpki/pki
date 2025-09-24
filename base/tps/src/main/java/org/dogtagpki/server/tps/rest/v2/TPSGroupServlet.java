//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.GroupServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsGroup",
        urlPatterns = "/v2/admin/groups/*")
public class TPSGroupServlet extends GroupServlet {
    private static final long serialVersionUID = 1L;
}
