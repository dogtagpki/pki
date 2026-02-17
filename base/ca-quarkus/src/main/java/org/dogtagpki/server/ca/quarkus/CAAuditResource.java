//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.AuditBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFile;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for CA audit operations.
 * Replaces CAAuditServlet.
 */
@Path("v2/audit")
public class CAAuditResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAuditResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditConfig() throws Exception {
        logger.debug("CAAuditResource.getAuditConfig()");
        CAEngine engine = engineQuarkus.getEngine();
        AuditBase audit = new AuditBase(engine);
        AuditConfig config = audit.getAuditConfig();
        return Response.ok(config.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuditConfig(String requestData) throws Exception {
        logger.debug("CAAuditResource.updateAuditConfig()");
        CAEngine engine = engineQuarkus.getEngine();
        AuditBase audit = new AuditBase(engine);
        AuditConfig config = JSONSerializer.fromJSON(requestData, AuditConfig.class);
        AuditConfig updatedConfig = audit.updateAuditConfig(config);
        return Response.ok(updatedConfig.toJSON()).build();
    }

    @GET
    @Path("files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listAuditFiles() throws Exception {
        logger.debug("CAAuditResource.listAuditFiles()");
        CAEngine engine = engineQuarkus.getEngine();
        AuditBase audit = new AuditBase(engine);
        AuditFileCollection files = audit.listAuditFiles();
        return Response.ok(files.toJSON()).build();
    }

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAuditFile(@PathParam("filename") String filename) throws Exception {
        logger.debug("CAAuditResource.getAuditFile(): {}", filename);
        CAEngine engine = engineQuarkus.getEngine();
        AuditBase audit = new AuditBase(engine);
        AuditFile file = audit.getAuditFile(filename);
        return Response.ok(file).build();
    }
}
