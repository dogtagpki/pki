//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.AccountServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tksAccount",
        urlPatterns = "/v2/account/*")
public class TKSAccountServlet extends AccountServlet {
    private static final long serialVersionUID = 1L;
}
