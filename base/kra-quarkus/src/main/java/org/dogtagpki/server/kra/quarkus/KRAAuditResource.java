//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.io.InputStream;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.rest.base.AuditServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFile;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for KRA audit operations.
 * Replaces KRAAuditServlet.
 */
@Path("v2/audit")
public class KRAAuditResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAAuditResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    private AuditServletBase createBase() {
        return new AuditServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditConfig() throws Exception {
        logger.debug("KRAAuditResource.getAuditConfig()");
        AuditConfig config = createBase().getAuditConfig();
        return Response.ok(config.toJSON()).build();
    }

    @PATCH
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuditConfig(String requestData) throws Exception {
        logger.debug("KRAAuditResource.updateAuditConfig()");
        AuditConfig auditConfig = JSONSerializer.fromJSON(requestData, AuditConfig.class);
        AuditConfig updated = createBase().updateAuditConfig(auditConfig);
        return Response.ok(updated.toJSON()).build();
    }

    @POST
    public Response changeAuditStatus(@QueryParam("action") String action) throws Exception {
        logger.debug("KRAAuditResource.changeAuditStatus(): action={}", action);
        createBase().changeAuditStatus(action);
        return Response.ok().build();
    }

    @GET
    @Path("files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditFiles() throws Exception {
        logger.debug("KRAAuditResource.getAuditFiles()");
        AuditFileCollection files = createBase().findAuditFiles();
        return Response.ok(files.toJSON()).build();
    }

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAuditFile(@PathParam("filename") String filename) throws Exception {
        logger.debug("KRAAuditResource.getAuditFile(): filename={}", filename);
        AuditFile auditFile = createBase().getAuditFile(filename);
        InputStream is = createBase().getAuditFileContent(filename);
        return Response.ok(is)
                .type(MediaType.APPLICATION_OCTET_STREAM)
                .header("Content-Disposition", "attachment; filename=\"" + auditFile.getName() + "\"")
                .build();
    }
}
