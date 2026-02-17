//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.io.File;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.rest.base.AuditServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFileCollection;

/**
 * JAX-RS resource for OCSP audit operations.
 * Replaces OCSPAuditServlet.
 */
@Path("v2/audit")
public class OCSPAuditResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPAuditResource.class);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    private AuditServletBase createBase() {
        return new AuditServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditConfig() throws Exception {
        logger.debug("OCSPAuditResource.getAuditConfig()");
        AuditConfig auditConfig = createBase().createAuditConfig();
        return Response.ok(auditConfig.toJSON()).build();
    }

    @PATCH
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuditConfig(String requestData) throws Exception {
        logger.debug("OCSPAuditResource.updateAuditConfig()");
        AuditConfig auditConfig = com.netscape.certsrv.util.JSONSerializer.fromJSON(requestData, AuditConfig.class);
        String principalName = securityContext.getUserPrincipal().getName();
        AuditConfig updatedConfig = createBase().updateAuditConfig(auditConfig, principalName);
        return Response.ok(updatedConfig.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAuditStatus(@QueryParam("action") String action) throws Exception {
        logger.debug("OCSPAuditResource.changeAuditStatus(): action={}", action);
        String principalName = securityContext.getUserPrincipal().getName();
        AuditConfig updatedConfig = createBase().changeAuditStatus(action, principalName);
        return Response.ok(updatedConfig.toJSON()).build();
    }

    @GET
    @Path("files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findAuditFiles() throws Exception {
        logger.debug("OCSPAuditResource.findAuditFiles()");
        AuditFileCollection files = createBase().findAuditFiles();
        return Response.ok(files.toJSON()).build();
    }

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAuditFile(@PathParam("filename") String fileName) throws Exception {
        logger.debug("OCSPAuditResource.getAuditFile(): filename={}", fileName);
        File auditFile = createBase().getAuditFile(fileName);
        return Response.ok(auditFile)
                .header("Content-Disposition", "attachment; filename=\"" + fileName + "\"")
                .build();
    }
}
