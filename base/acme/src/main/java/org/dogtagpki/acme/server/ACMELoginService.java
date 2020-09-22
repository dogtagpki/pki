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
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.catalina.realm.GenericPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;

/**
 * @author Endi S. Dewata
 */
@Path("login")
public class ACMELoginService {

    public static Logger logger = LoggerFactory.getLogger(ACMELoginService.class);

    @Context
    protected HttpServletRequest servletRequest;

    protected Account createAccount() {

        Principal principal = servletRequest.getUserPrincipal();
        String username = principal.getName();
        logger.info("ACMELoginService: Principal: " + username);

        Account account = new Account();
        account.setID(username);

        if (principal instanceof GenericPrincipal) {
            String[] roles = ((GenericPrincipal) principal).getRoles();
            logger.info("ACMELoginService: Roles:");
            for (String role : roles) {
                logger.info("ACMELoginService: - " + role);
            }
            account.setRoles(Arrays.asList(roles));
        }

        return account;
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST() {

        HttpSession session = servletRequest.getSession();
        logger.info("ACMELoginService: Creating session " + session.getId());

        Account account = createAccount();

        ResponseBuilder builder = Response.ok();
        builder.entity(account);
        return builder.build();
    }
}
