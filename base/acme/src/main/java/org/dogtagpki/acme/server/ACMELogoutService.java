//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

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
