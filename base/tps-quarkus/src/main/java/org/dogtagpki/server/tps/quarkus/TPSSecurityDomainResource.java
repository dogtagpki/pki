//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.Collection;
import java.util.Locale;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.rest.base.SecurityDomainServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.util.JSONSerializer;

@Path("v2/securityDomain")
public class TPSSecurityDomainResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSSecurityDomainResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    private SecurityDomainServletBase createBase() {
        return new SecurityDomainServletBase(engineQuarkus.getEngine(), Locale.getDefault());
    }

    @GET
    @Path("installToken")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getInstallToken(
            @QueryParam("hostname") String hostname,
            @QueryParam("subsystem") String subsystem) throws Exception {
        logger.debug("TPSSecurityDomainResource.getInstallToken(): hostname={}, subsystem={}", hostname, subsystem);
        if (subsystem == null || subsystem.isBlank()) {
            throw new BadRequestException("Missing subsystem parameter");
        }
        String principalName = securityContext.getUserPrincipal().getName();
        InstallToken token = createBase().getInstallToken(hostname, subsystem, principalName);
        return Response.ok(token.toJSON()).build();
    }

    @GET
    @Path("domainInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDomainInfo() throws Exception {
        logger.debug("TPSSecurityDomainResource.getDomainInfo()");
        DomainInfo domain = createBase().getDomainInfo();
        return Response.ok(domain.toJSON()).build();
    }

    @GET
    @Path("hosts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getHosts() throws Exception {
        logger.debug("TPSSecurityDomainResource.getHosts()");
        Collection<SecurityDomainHost> hosts = createBase().getHosts();
        ObjectMapper mapper = new ObjectMapper();
        return Response.ok(mapper.writeValueAsString(hosts)).build();
    }

    @GET
    @Path("hosts/{hostId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getHost(@PathParam("hostId") String hostId) throws Exception {
        logger.debug("TPSSecurityDomainResource.getHost(): hostId={}", hostId);
        SecurityDomainHost host = createBase().getHost(hostId);
        return Response.ok(host.toJSON()).build();
    }

    @PUT
    @Path("hosts")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addHost(String requestData) throws Exception {
        logger.debug("TPSSecurityDomainResource.addHost()");
        SecurityDomainHost host = JSONSerializer.fromJSON(requestData, SecurityDomainHost.class);
        createBase().addHost(host);
        return Response.noContent().build();
    }

    @DELETE
    @Path("hosts/{hostId}")
    public Response removeHost(@PathParam("hostId") String hostId) throws Exception {
        logger.debug("TPSSecurityDomainResource.removeHost(): hostId={}", hostId);
        createBase().removeHost(hostId);
        return Response.noContent().build();
    }
}
