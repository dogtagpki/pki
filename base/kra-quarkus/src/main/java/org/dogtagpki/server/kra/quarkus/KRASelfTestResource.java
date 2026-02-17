//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

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
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;

/**
 * JAX-RS resource for KRA self-test operations.
 * Replaces KRASelfTestServlet.
 */
@Path("v2/selftests")
public class KRASelfTestResource {

    private static final Logger logger = LoggerFactory.getLogger(KRASelfTestResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    private SelfTestServletBase createBase() {
        return new SelfTestServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findTests(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        logger.debug("KRASelfTestResource.findTests()");
        SelfTestCollection tests = createBase().findSelfTests(filter, start, size);
        return Response.ok(tests.toJSON()).build();
    }

    @GET
    @Path("{testId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTest(@PathParam("testId") String testId) throws Exception {
        logger.debug("KRASelfTestResource.getTest(): testId={}", testId);
        SelfTestData test = createBase().getSelfTest(testId);
        return Response.ok(test.toJSON()).build();
    }

    @POST
    public Response executeTests(@QueryParam("action") String action) throws Exception {
        logger.debug("KRASelfTestResource.executeTests(): action={}", action);
        createBase().executeSelfTests(action);
        return Response.noContent().build();
    }

    @POST
    @Path("run")
    @Produces(MediaType.APPLICATION_JSON)
    public Response runTests() throws Exception {
        logger.debug("KRASelfTestResource.runTests()");
        SelfTestResults results = createBase().runSelfTests();
        return Response.ok(results.toJSON()).build();
    }

    @POST
    @Path("{testId}/run")
    @Produces(MediaType.APPLICATION_JSON)
    public Response runTest(@PathParam("testId") String testId) throws Exception {
        logger.debug("KRASelfTestResource.runTest(): testId={}", testId);
        SelfTestResult result = createBase().runSelfTest(testId);
        return Response.ok(result.toJSON()).build();
    }
}
