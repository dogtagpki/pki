//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class AccountServletBase {

    public static final Logger logger = LoggerFactory.getLogger(AccountServletBase.class);

    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if(request.getPathInfo() == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }
        String operation = request.getPathInfo().substring(1);
        if (operation.equals("login")) {
            HttpSession session = request.getSession();
            logger.info("Creating session {}", session.getId());

            Account account = createAccount(request.getUserPrincipal());
            PrintWriter out = response.getWriter();
            out.println(account.toJSON());
            return;
        }
        if (operation.equals("logout")) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.info("Destroying session {}", session.getId());
                session.invalidate();
            }
            return;
        }
        response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
    }


    protected Account createAccount(Principal principal) {
        logger.info("Principal:");

        Account account = new Account();
        String name = principal.getName();
        logger.info("- ID: {}", name);
        account.setID(name);

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            User user = pkiPrincipal.getUser();

            String fullName = user.getFullName();
            logger.info("- Full Name: {}", fullName);
            if (!StringUtils.isEmpty(fullName)) account.setFullName(fullName);

            String email = user.getEmail();
            logger.info("- Email: {}", email);
            if (!StringUtils.isEmpty(email)) account.setEmail(email);
        }

        if (principal instanceof GenericPrincipal genericPrincipal) {
            String[] roles = genericPrincipal.getRoles();
            logger.info("Roles:");
            for (String role : roles) {
                logger.info("- {}", role);
            }
            account.setRoles(Arrays.asList(roles));
        }

        return account;
    }

}
