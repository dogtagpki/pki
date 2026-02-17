//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

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

import org.dogtagpki.server.kra.rest.base.KeyProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.util.JSONSerializer;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for KRA key operations.
 * Replaces KeyServlet.
 *
 * Note: Key operations require PKIPrincipal for realm-based
 * authorization. The SecurityIdentity is converted to PKIPrincipal
 * via KRAEngineQuarkus.toPKIPrincipal() to support the existing
 * KeyProcessor authorization model.
 */
@Path("v2/agent/keys")
public class KRAKeyResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAKeyResource.class);
    private static final int DEFAULT_MAXRESULTS = 100;
    private static final int DEFAULT_MAXTIME = 10;
    private static final int DEFAULT_SIZE = 20;

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @Context
    UriInfo uriInfo;

    private KeyProcessor createProcessor() {
        return new KeyProcessor(engineQuarkus.getEngine());
    }

    private Principal getPrincipal() {
        return KRAEngineQuarkus.toPKIPrincipal(identity);
    }

    private String getBaseUrl() {
        return uriInfo.getBaseUri().toString() + "v2/agent/keys";
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listKeys(
            @QueryParam("clientKeyID") String clientKeyID,
            @QueryParam("status") String status,
            @QueryParam("maxResults") @DefaultValue("100") int maxResults,
            @QueryParam("maxTime") @DefaultValue("10") int maxTime,
            @QueryParam("pageSize") @DefaultValue("20") int size,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("realm") String realm,
            @QueryParam("owner") String owner) throws Exception {
        logger.debug("KRAKeyResource.listKeys()");
        KeyInfoCollection keys = createProcessor().listKeys(
                getPrincipal(), getBaseUrl(), clientKeyID, status,
                maxResults, maxTime, start, size, realm, owner);
        return Response.ok(keys.toJSON()).build();
    }

    @GET
    @Path("{keyId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getKeyInfo(@PathParam("keyId") String keyIdStr) throws Exception {
        logger.debug("KRAKeyResource.getKeyInfo(): keyId={}", keyIdStr);
        KeyId keyId = new KeyId(keyIdStr);
        KeyInfo info = createProcessor().getKeyInfo(getPrincipal(), getBaseUrl(), keyId);
        return Response.ok(info.toJSON()).build();
    }

    @GET
    @Path("active/{clientKeyID}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActiveKeyInfo(@PathParam("clientKeyID") String clientKeyID) throws Exception {
        logger.debug("KRAKeyResource.getActiveKeyInfo(): clientKeyID={}", clientKeyID);
        KeyInfo info = createProcessor().getActiveKeyInfo(getPrincipal(), getBaseUrl(), clientKeyID);
        return Response.ok(info.toJSON()).build();
    }

    @POST
    @Path("{keyId}")
    public Response modifyKeyStatus(
            @PathParam("keyId") String keyIdStr,
            @QueryParam("status") String status) throws Exception {
        logger.debug("KRAKeyResource.modifyKeyStatus(): keyId={}, status={}", keyIdStr, status);
        KeyId keyId = new KeyId(keyIdStr);
        createProcessor().modifyKeyStatus(getPrincipal(), getBaseUrl(), keyId, status);
        return Response.noContent().build();
    }

    @POST
    @Path("retrieve")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveKey(String requestData) throws Exception {
        logger.debug("KRAKeyResource.retrieveKey()");
        KeyRecoveryRequest data = JSONSerializer.fromJSON(requestData, KeyRecoveryRequest.class);
        KeyData keyData = createProcessor().retrieveKey(getPrincipal(), data);
        return Response.ok(keyData.toJSON()).build();
    }
}
