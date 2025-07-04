//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.server.tps.TPSAccountServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsAccount",
        urlPatterns = "/v2/account/*")
public class TPSAccountServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(TPSAccountServlet.class);

    @WebAction(method = HttpMethod.GET, paths = { "login"})
    public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.info("AccountServlet: Creating session {}", session.getId());
        Account account = TPSAccountServletBase.createAccount(request.getUserPrincipal());
        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }
    @WebAction(method = HttpMethod.GET, paths = { "logout"})
    public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.info("AccountServlet: Destroying session {}", session.getId());
            session.invalidate();
        }
    }
}
