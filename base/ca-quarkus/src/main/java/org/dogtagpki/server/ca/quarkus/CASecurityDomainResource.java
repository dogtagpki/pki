//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.SecurityDomainBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;

/**
 * JAX-RS resource for CA security domain operations.
 * Replaces CASecurityDomainServlet.
 */
@Path("v2/securityDomain")
public class CASecurityDomainResource {

    private static final Logger logger = LoggerFactory.getLogger(CASecurityDomainResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Path("domainInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDomainInfo() throws Exception {
        logger.debug("CASecurityDomainResource.getDomainInfo()");
        CAEngine engine = engineQuarkus.getEngine();
        SecurityDomainBase sdBase = new SecurityDomainBase(engine);
        DomainInfo info = sdBase.getDomainInfo();
        return Response.ok(info.toJSON()).build();
    }

    @GET
    @Path("installToken")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getInstallToken(@QueryParam("hostname") String hostname) throws Exception {
        logger.debug("CASecurityDomainResource.getInstallToken(): hostname={}", hostname);
        CAEngine engine = engineQuarkus.getEngine();
        SecurityDomainBase sdBase = new SecurityDomainBase(engine);
        InstallToken token = sdBase.getInstallToken(hostname);
        return Response.ok(token.toJSON()).build();
    }
}
