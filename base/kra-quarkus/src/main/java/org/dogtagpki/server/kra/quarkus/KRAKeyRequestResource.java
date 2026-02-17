//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.net.URLEncoder;
import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.dogtagpki.server.kra.rest.base.KeyRequestProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for KRA key request operations.
 * Replaces KeyRequestServlet.
 *
 * Note: Key request operations require PKIPrincipal for realm-based
 * authorization. The SecurityIdentity is converted to PKIPrincipal
 * via KRAEngineQuarkus.toPKIPrincipal() to support the existing
 * KeyRequestProcessor authorization model.
 */
@Path("v2/agent/keyrequests")
public class KRAKeyRequestResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAKeyRequestResource.class);
    private static final int DEFAULT_MAXTIME = 10;
    private static final int DEFAULT_SIZE = 20;

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private KeyRequestProcessor createProcessor() {
        return new KeyRequestProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return KRAEngineQuarkus.toPKIPrincipal(identity);
    }

    private String getBaseUrl() {
        return uriInfo.getBaseUri().toString() + "v2/agent/keyrequests";
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listRequests(
            @QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @QueryParam("clientKeyID") String clientKeyID,
            @QueryParam("maxTime") @DefaultValue("10") int maxTime,
            @QueryParam("pageSize") @DefaultValue("20") int size,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("realm") String realm) throws Exception {
        logger.debug("KRAKeyRequestResource.listRequests()");
        KeyRequestInfoCollection requests = createProcessor().listRequests(
                getPrincipal(), getBaseUrl(), requestState, requestType,
                clientKeyID, maxTime, start, size, realm);
        return Response.ok(requests.toJSON()).build();
    }

    @GET
    @Path("{requestId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequestInfo(@PathParam("requestId") String requestIdStr) throws Exception {
        logger.debug("KRAKeyRequestResource.getRequestInfo(): requestId={}", requestIdStr);
        RequestId id = new RequestId(requestIdStr);
        KeyRequestInfo info = createProcessor().getRequestInfo(getPrincipal(), getBaseUrl(), id);
        return Response.ok(info.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response submitRequest(String requestData) throws Exception {
        logger.debug("KRAKeyRequestResource.submitRequest()");
        RESTMessage data = JSONSerializer.fromJSON(requestData, RESTMessage.class);
        KeyRequestResponse response = createProcessor().submitRequest(
                getPrincipal(), getBaseUrl(), data);

        String encodedID = URLEncoder.encode(
                response.getRequestId().toHexString(), "UTF-8");
        java.net.URI location = uriInfo.getAbsolutePathBuilder()
                .path(encodedID).build();

        return Response.created(location).entity(response.toJSON()).build();
    }

    @POST
    @Path("{requestId}/approve")
    public Response approveRequest(@PathParam("requestId") String requestIdStr) throws Exception {
        logger.debug("KRAKeyRequestResource.approveRequest(): requestId={}", requestIdStr);
        RequestId id = new RequestId(requestIdStr);
        createProcessor().approve(getPrincipal(), id);
        return Response.noContent().build();
    }

    @POST
    @Path("{requestId}/reject")
    public Response rejectRequest(@PathParam("requestId") String requestIdStr) throws Exception {
        logger.debug("KRAKeyRequestResource.rejectRequest(): requestId={}", requestIdStr);
        RequestId id = new RequestId(requestIdStr);
        createProcessor().reject(getPrincipal(), id);
        return Response.noContent().build();
    }

    @POST
    @Path("{requestId}/cancel")
    public Response cancelRequest(@PathParam("requestId") String requestIdStr) throws Exception {
        logger.debug("KRAKeyRequestResource.cancelRequest(): requestId={}", requestIdStr);
        RequestId id = new RequestId(requestIdStr);
        createProcessor().cancel(getPrincipal(), id);
        return Response.noContent().build();
    }
}
