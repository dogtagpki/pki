//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import java.net.URLEncoder;
import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.server.tks.rest.base.TPSConnectorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TKS TPS connector operations.
 * Replaces TPSConnectorServlet.
 *
 * TPS connector operations manage the secure communication
 * channel between TKS and TPS, including AES-128 shared
 * secret generation and lifecycle management.
 *
 * Shared secret operations require PKIPrincipal for user
 * validation. The SecurityIdentity is converted to PKIPrincipal
 * via TKSEngineQuarkus.toPKIPrincipal().
 */
@Path("v2/admin/tps-connectors")
public class TKSTPSConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSTPSConnectorResource.class);

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private TPSConnectorProcessor createProcessor() {
        return new TPSConnectorProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return TKSEngineQuarkus.toPKIPrincipal(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findConnectors(
            @QueryParam("host") String host,
            @QueryParam("port") String port,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("pageSize") @DefaultValue("20") int size) throws Exception {
        logger.debug("TKSTPSConnectorResource.findConnectors()");
        TPSConnectorCollection connectors = createProcessor().findConnectors(host, port, start, size);
        return Response.ok(connectors.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createConnector(
            @QueryParam("host") String host,
            @QueryParam("port") String port) throws Exception {
        logger.debug("TKSTPSConnectorResource.createConnector(): host={}, port={}", host, port);
        TPSConnectorData connector = createProcessor().createConnector(getPrincipal(), host, port);
        String encodedID = URLEncoder.encode(connector.getID(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder().path(encodedID).build();
        return Response.created(location).entity(connector.toJSON()).build();
    }

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteConnectorByHost(
            @QueryParam("host") String host,
            @QueryParam("port") String port) throws Exception {
        logger.debug("TKSTPSConnectorResource.deleteConnectorByHost(): host={}, port={}", host, port);
        createProcessor().deleteConnector(host, port);
        return Response.noContent().build();
    }

    @GET
    @Path("{connectorId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnector(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.getConnector(): connectorId={}", connectorId);
        TPSConnectorData connector = createProcessor().getConnector(connectorId);
        return Response.ok(connector.toJSON()).build();
    }

    @POST
    @Path("{connectorId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyConnector(
            @PathParam("connectorId") String connectorId,
            String requestData) throws Exception {
        logger.debug("TKSTPSConnectorResource.modifyConnector(): connectorId={}", connectorId);
        TPSConnectorData data = JSONSerializer.fromJSON(requestData, TPSConnectorData.class);
        TPSConnectorData connector = createProcessor().updateConnector(connectorId, data);
        return Response.ok(connector.toJSON()).build();
    }

    @DELETE
    @Path("{connectorId}")
    public Response deleteConnector(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.deleteConnector(): connectorId={}", connectorId);
        createProcessor().deleteConnector(connectorId);
        return Response.noContent().build();
    }

    @GET
    @Path("{connectorId}/shared-secret")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedSecret(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.getSharedSecret(): connectorId={}", connectorId);
        KeyData key = createProcessor().getSharedSecret(getPrincipal(), connectorId);
        if (key == null) {
            return Response.noContent().build();
        }
        return Response.ok(key.toJSON()).build();
    }

    @POST
    @Path("{connectorId}/shared-secret")
    @Produces(MediaType.APPLICATION_JSON)
    public Response createSharedSecret(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.createSharedSecret(): connectorId={}", connectorId);
        KeyData key = createProcessor().createSharedSecret(getPrincipal(), connectorId);
        if (key == null) {
            return Response.noContent().build();
        }
        return Response.ok(key.toJSON()).build();
    }

    @PUT
    @Path("{connectorId}/shared-secret")
    @Produces(MediaType.APPLICATION_JSON)
    public Response replaceSharedSecret(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.replaceSharedSecret(): connectorId={}", connectorId);
        KeyData key = createProcessor().replaceSharedSecret(getPrincipal(), connectorId);
        if (key == null) {
            return Response.noContent().build();
        }
        return Response.ok(key.toJSON()).build();
    }

    @DELETE
    @Path("{connectorId}/shared-secret")
    public Response deleteSharedSecret(@PathParam("connectorId") String connectorId) throws Exception {
        logger.debug("TKSTPSConnectorResource.deleteSharedSecret(): connectorId={}", connectorId);
        createProcessor().deleteSharedSecret(connectorId);
        return Response.noContent().build();
    }
}
