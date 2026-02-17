//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;

/**
 * JAX-RS resource for CA KRA connector operations.
 * Replaces KRAConnectorServlet.
 */
@Path("v2/admin/kraconnector")
public class CAKRAConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(CAKRAConnectorResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnectorInfo() throws Exception {
        logger.debug("CAKRAConnectorResource.getConnectorInfo()");
        CAEngine engine = engineQuarkus.getEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
            KRAConnectorInfo connector = processor.getConnectorInfo();
            return Response.ok(connector.toJSON()).build();
        } catch (EBaseException e) {
            throw new PKIException("Unable to get KRA connector: " + e.getMessage(), e);
        }
    }

    @POST
    @Path("add")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addConnector(String requestData) throws Exception {
        logger.debug("CAKRAConnectorResource.addConnector()");
        CAEngine engine = engineQuarkus.getEngine();
        KRAConnectorInfo connector = JSONSerializer.fromJSON(requestData, KRAConnectorInfo.class);

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
            processor.addConnector(connector);
        } catch (EBaseException e) {
            throw new PKIException("Unable to add KRA connector: " + e.getMessage(), e);
        }
        return Response.noContent().build();
    }

    @POST
    @Path("remove")
    public Response removeConnector(
            @QueryParam("host") String host,
            @QueryParam("port") String port) throws Exception {
        logger.debug("CAKRAConnectorResource.removeConnector()");
        CAEngine engine = engineQuarkus.getEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
            processor.removeConnector(host, port);
        } catch (EBaseException e) {
            throw new PKIException("Unable to remove KRA connector: " + e.getMessage(), e);
        }
        return Response.noContent().build();
    }

    @POST
    @Path("addHost")
    public Response addHost(
            @QueryParam("host") String host,
            @QueryParam("port") String port) throws Exception {
        logger.debug("CAKRAConnectorResource.addHost()");
        CAEngine engine = engineQuarkus.getEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
            processor.addHost(host, port);
        } catch (EBaseException e) {
            throw new PKIException("Unable to add KRA connector host: " + e.getMessage(), e);
        }
        return Response.noContent().build();
    }
}
