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
import org.dogtagpki.server.rest.base.JobBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.jobs.JobCollection;
import com.netscape.certsrv.jobs.JobData;

/**
 * JAX-RS resource for CA job operations.
 * Replaces CAJobServlet.
 */
@Path("v2/jobs")
public class CAJobResource {

    private static final Logger logger = LoggerFactory.getLogger(CAJobResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findJobs(
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        JobBase jobBase = new JobBase(engine);
        JobCollection jobs = jobBase.findJobs(start, size);
        return Response.ok(jobs.toJSON()).build();
    }

    @GET
    @Path("{jobId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJob(@PathParam("jobId") String jobId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        JobBase jobBase = new JobBase(engine);
        JobData job = jobBase.getJob(jobId);
        return Response.ok(job.toJSON()).build();
    }

    @POST
    @Path("{jobId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response startJob(@PathParam("jobId") String jobId) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        JobBase jobBase = new JobBase(engine);
        jobBase.startJob(jobId);
        return Response.noContent().build();
    }
}
