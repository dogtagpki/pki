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
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.SelfTestBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;

/**
 * JAX-RS resource for CA self-test operations.
 * Replaces CASelfTestServlet.
 */
@Path("v2/selftests")
public class CASelfTestResource {

    private static final Logger logger = LoggerFactory.getLogger(CASelfTestResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findSelfTests(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        SelfTestBase selfTestBase = new SelfTestBase(engine);
        SelfTestCollection tests = selfTestBase.findSelfTests(filter, start, size);
        return Response.ok(tests.toJSON()).build();
    }

    @POST
    @Path("run")
    @Produces(MediaType.APPLICATION_JSON)
    public Response runSelfTests() throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        SelfTestBase selfTestBase = new SelfTestBase(engine);
        selfTestBase.runSelfTests();
        return Response.noContent().build();
    }
}
