//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.rest.v2.AccountServletBase;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "ocspAccount",
        urlPatterns = "/v2/account/*")
public class AccountServlet extends OCSPServlet {
    private static final long serialVersionUID = 1L;

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        AccountServletBase accountServlet = new AccountServletBase();
        accountServlet.get(request, response);
    }
}
