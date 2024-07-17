//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.AccountServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "kraAccount",
        urlPatterns = "/v2/account/*")
public class AccountKRAServlet extends AccountServlet {
    private static final long serialVersionUID = 1L;
}
