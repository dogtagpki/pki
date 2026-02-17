//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.rest.base.JobServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.jobs.JobCollection;
import com.netscape.certsrv.jobs.JobInfo;

/**
 * JAX-RS resource for TKS job operations.
 * Replaces TKSJobServlet.
 */
@Path("v2/jobs")
public class TKSJobResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSJobResource.class);

    @Inject
    TKSEngineQuarkus engineQuarkus;

    private JobServletBase createBase() {
        return new JobServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJobs() throws Exception {
        logger.debug("TKSJobResource.getJobs()");
        JobCollection jobs = createBase().getJobs();
        return Response.ok(jobs.toJSON()).build();
    }

    @GET
    @Path("{jobId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJob(@PathParam("jobId") String jobId) throws Exception {
        logger.debug("TKSJobResource.getJob(): jobId={}", jobId);
        JobInfo job = createBase().getJob(jobId);
        return Response.ok(job.toJSON()).build();
    }

    @POST
    @Path("{jobId}/start")
    public Response startJob(@PathParam("jobId") String jobId) throws Exception {
        logger.debug("TKSJobResource.startJob(): jobId={}", jobId);
        createBase().startJob(jobId);
        return Response.noContent().build();
    }
}
