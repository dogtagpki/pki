//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.base.WebAction;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.usrgrp.User;

/**
 * ACME Login.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeLoginServlet",
        urlPatterns = "/login/*")
public class ACMELoginServlet extends ACMEServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMELoginServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(false); // don't create new session
        logger.info("ACMELoginServlet: Session: {}", (session == null ? null : session.getId()));

        if (session == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }

        Principal principal = request.getUserPrincipal();
        logger.info("ACMELoginServlet: Principal: " + principal);

        if (principal == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }

        Account account = createAccount(principal);
        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void postLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(); // create new session if necessary
        logger.info("ACMELoginServlet: Session: {}", session.getId());

        Principal principal = request.getUserPrincipal();
        logger.info("ACMELoginServlet: Principal: " + principal);

        Account account = createAccount(principal);
        PrintWriter out = response.getWriter();
        out.println(account.toJSON());
    }

    protected Account createAccount(Principal principal) {

        String username = principal.getName();
        logger.info("ACMELoginServlet: Principal: " + username);

        Account account = new Account();
        account.setID(username);

        if (principal instanceof PKIPrincipal pkiPrincipal) {

            User user = pkiPrincipal.getUser();
            account.setFullName(user.getFullName());
            account.setEmail(user.getEmail());

            String[] roles = pkiPrincipal.getRoles();
            logger.info("ACMELoginServlet: Roles:");
            for (String role : roles) {
                logger.info("ACMELoginServlet: - " + role);
            }
            account.setRoles(Arrays.asList(roles));
        }

        return account;
    }
}
