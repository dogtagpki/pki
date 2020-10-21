//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.security.Principal;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
@Path("login")
public class ACMELoginService {

    public static Logger logger = LoggerFactory.getLogger(ACMELoginService.class);

    @Context
    protected HttpServletRequest servletRequest;

    protected Account createAccount(Principal principal) {

        String username = principal.getName();
        logger.info("ACMELoginService: Principal: " + username);

        Account account = new Account();
        account.setID(username);

        if (principal instanceof PKIPrincipal) {
            PKIPrincipal pkiPrincipal = (PKIPrincipal) principal;

            User user = pkiPrincipal.getUser();
            account.setFullName(user.getFullName());
            account.setEmail(user.getEmail());

            String[] roles = pkiPrincipal.getRoles();
            logger.info("ACMELoginService: Roles:");
            for (String role : roles) {
                logger.info("ACMELoginService: - " + role);
            }
            account.setRoles(Arrays.asList(roles));
        }

        return account;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response handleGET() {

        HttpSession session = servletRequest.getSession(false); // don't create new session
        logger.info("ACMELoginService: Session: " + (session == null ? null : session.getId()));

        if (session == null) {
            ResponseBuilder builder = Response.noContent();
            return builder.build();
        }

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("ACMELoginService: Principal: " + principal);

        if (principal == null) {
            ResponseBuilder builder = Response.noContent();
            return builder.build();
        }

        ResponseBuilder builder = Response.ok();
        Account account = createAccount(principal);
        builder.entity(account);
        return builder.build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST() {

        HttpSession session = servletRequest.getSession(); // create new session if necessary
        logger.info("ACMELoginService: Session: " + session.getId());

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("ACMELoginService: Principal: " + principal);

        Account account = createAccount(principal);

        ResponseBuilder builder = Response.ok();
        builder.entity(account);
        return builder.build();
    }
}
