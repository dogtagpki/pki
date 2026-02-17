//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.net.URLEncoder;
import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
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
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.rest.base.ConnectorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.tps.connector.ConnectorCollection;
import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS connector operations.
 * Replaces ConnectorServlet.
 */
@Path("v2/connectors")
public class TPSConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSConnectorResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private ConnectorProcessor createProcessor() {
        return new ConnectorProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return TPSEngineQuarkus.toPKIPrincipal(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findConnectors(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("pageSize") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSConnectorResource.findConnectors()");
        ConnectorCollection connectors = createProcessor().findConnectors(filter, start, size);
        return Response.ok(connectors.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addConnector(String requestData) throws Exception {
        logger.debug("TPSConnectorResource.addConnector()");
        ConnectorData data = JSONSerializer.fromJSON(requestData, ConnectorData.class);
        ConnectorData connector = createProcessor().addConnector(getPrincipal(), data);
        String encodedID = URLEncoder.encode(connector.getID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(connector.toJSON()).build();
    }

    @GET
    @Path("{connectorId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnector(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TPSConnectorResource.getConnector(): id={}", connectorId);
        ConnectorData connector = createProcessor().getConnector(connectorId);
        return Response.ok(connector.toJSON()).build();
    }

    @PATCH
    @Path("{connectorId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConnector(
            @PathParam("connectorId") String connectorId,
            String requestData) throws Exception {
        logger.debug("TPSConnectorResource.updateConnector(): id={}", connectorId);
        ConnectorData data = JSONSerializer.fromJSON(requestData, ConnectorData.class);
        ConnectorData connector = createProcessor().updateConnector(getPrincipal(), connectorId, data);
        return Response.ok(connector.toJSON()).build();
    }

    @POST
    @Path("{connectorId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeStatus(
            @PathParam("connectorId") String connectorId,
            @QueryParam("action") String action) throws Exception {
        logger.debug("TPSConnectorResource.changeStatus(): id={}, action={}", connectorId, action);
        ConnectorData connector = createProcessor().changeStatus(getPrincipal(), connectorId, action);
        return Response.ok(connector.toJSON()).build();
    }

    @DELETE
    @Path("{connectorId}")
    public Response removeConnector(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TPSConnectorResource.removeConnector(): id={}", connectorId);
        createProcessor().removeConnector(getPrincipal(), connectorId);
        return Response.noContent().build();
    }
}
