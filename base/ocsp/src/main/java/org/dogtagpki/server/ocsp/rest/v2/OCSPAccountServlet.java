//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2;

import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.AccountServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "ocspAccount",
        urlPatterns = "/v2/account/*")
public class OCSPAccountServlet extends AccountServlet {
    private static final long serialVersionUID = 1L;
}
