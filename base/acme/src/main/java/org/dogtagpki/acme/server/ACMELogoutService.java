//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Endi S. Dewata
 */
@Path("logout")
public class ACMELogoutService {

    public static Logger logger = LoggerFactory.getLogger(ACMELogoutService.class);

    @Context
    protected HttpServletRequest servletRequest;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST() {

        HttpSession session = servletRequest.getSession(false);

        if (session != null) {
            logger.info("ACMELogoutService: Destroying session " + session.getId());
            session.invalidate();
        }

        ResponseBuilder builder = Response.noContent();
        return builder.build();
    }
}
