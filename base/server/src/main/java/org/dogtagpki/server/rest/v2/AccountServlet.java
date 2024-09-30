//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.rest.base.AccountServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class AccountServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(AccountServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {"login"})
    public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.info("AccountServlet: Creating session {}", session.getId());

        Account account = AccountServletBase.createAccount(request.getUserPrincipal());
        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"logout"})
    public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.info("AccountServlet: Destroying session {}", session.getId());
            session.invalidate();
        }
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
    }
}
