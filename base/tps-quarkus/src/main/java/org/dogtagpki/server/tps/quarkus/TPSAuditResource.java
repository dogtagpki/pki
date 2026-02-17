//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import jakarta.inject.Inject;
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

@Path("v2/audit")
public class TPSAuditResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSAuditResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    private AuditServletBase createBase() {
        return new AuditServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditConfig() throws Exception {
        logger.debug("TPSAuditResource.getAuditConfig()");
        AuditConfig config = createBase().getAuditConfig();
        return Response.ok(config.toJSON()).build();
    }

    @PATCH
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuditConfig(String requestData) throws Exception {
        logger.debug("TPSAuditResource.updateAuditConfig()");
        AuditConfig config = createBase().updateAuditConfig(requestData);
        return Response.ok(config.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAuditStatus(@QueryParam("action") String action) throws Exception {
        logger.debug("TPSAuditResource.changeAuditStatus(): action={}", action);
        AuditConfig config = createBase().changeAuditStatus(action);
        return Response.ok(config.toJSON()).build();
    }

    @GET
    @Path("files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response findAuditFiles() throws Exception {
        logger.debug("TPSAuditResource.findAuditFiles()");
        AuditFileCollection files = createBase().findAuditFiles();
        return Response.ok(files.toJSON()).build();
    }

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAuditFile(@PathParam("filename") String filename) throws Exception {
        logger.debug("TPSAuditResource.getAuditFile(): filename={}", filename);
        AuditFile auditFile = createBase().getAuditFile(filename);
        File file = new File(auditFile.getName());
        InputStream is = new FileInputStream(file);
        return Response.ok(is)
                .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                .build();
    }
}
