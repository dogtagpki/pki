//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.rest.base.SelfTestServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.certsrv.selftests.SelfTestResults;

@Path("v2/selftests")
public class TPSSelfTestResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSSelfTestResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    private SelfTestServletBase createBase() {
        return new SelfTestServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findSelfTests(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSSelfTestResource.findSelfTests()");
        SelfTestCollection tests = createBase().findSelfTests(filter, start, size);
        return Response.ok(tests.toJSON()).build();
    }

    @GET
    @Path("{testId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSelfTest(@PathParam("testId") String testId) throws Exception {
        logger.debug("TPSSelfTestResource.getSelfTest(): testId={}", testId);
        SelfTestData test = createBase().getSelfTest(testId);
        return Response.ok(test.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response executeSelfTests(@QueryParam("action") String action) throws Exception {
        logger.debug("TPSSelfTestResource.executeSelfTests(): action={}", action);
        createBase().executeSelfTests(action);
        return Response.noContent().build();
    }

    @POST
    @Path("run")
    @Produces(MediaType.APPLICATION_JSON)
    public Response runSelfTests() throws Exception {
        logger.debug("TPSSelfTestResource.runSelfTests()");
        SelfTestResults results = createBase().runSelfTests();
        return Response.ok(results.toJSON()).build();
    }

    @POST
    @Path("{testId}/run")
    @Produces(MediaType.APPLICATION_JSON)
    public Response runSelfTest(@PathParam("testId") String testId) throws Exception {
        logger.debug("TPSSelfTestResource.runSelfTest(): testId={}", testId);
        SelfTestResults results = createBase().runSelfTest(testId);
        return Response.ok(results.toJSON()).build();
    }
}
