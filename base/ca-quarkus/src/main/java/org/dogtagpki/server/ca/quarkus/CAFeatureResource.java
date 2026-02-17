//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.FeatureBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureCollection;

/**
 * JAX-RS resource for CA feature operations.
 * Replaces CAFeatureServlet.
 */
@Path("v2/config/features")
public class CAFeatureResource {

    private static final Logger logger = LoggerFactory.getLogger(CAFeatureResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listFeatures(
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        FeatureBase featureBase = new FeatureBase(engine);
        FeatureCollection features = featureBase.listFeatures(start, size);
        return Response.ok(features.toJSON()).build();
    }

    @GET
    @Path("{featureId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getFeature(@PathParam("featureId") String featureId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        FeatureBase featureBase = new FeatureBase(engine);
        Feature feature = featureBase.getFeature(featureId);
        return Response.ok(feature.toJSON()).build();
    }
}
