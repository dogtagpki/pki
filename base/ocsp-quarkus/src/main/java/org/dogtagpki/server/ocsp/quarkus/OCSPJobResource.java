//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.security.Principal;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.server.rest.base.JobServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JAX-RS resource for OCSP job management.
 * Replaces OCSPJobServlet.
 */
@Path("v2/jobs")
public class OCSPJobResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPJobResource.class);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    private JobServletBase createBase() {
        return new JobServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJobs() throws Exception {
        logger.debug("OCSPJobResource.getJobs()");
        Principal principal = securityContext.getUserPrincipal();
        JobCollection jobs = createBase().findJobs(principal);
        return Response.ok(jobs.toJSON()).build();
    }

    @GET
    @Path("{jobId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJob(@PathParam("jobId") String jobId) throws Exception {
        logger.debug("OCSPJobResource.getJob(): jobId={}", jobId);
        Principal principal = securityContext.getUserPrincipal();
        JobInfo job = createBase().getJob(jobId, principal);
        return Response.ok(job.toJSON()).build();
    }

    @POST
    @Path("{jobId}/start")
    public Response startJob(@PathParam("jobId") String jobId) throws Exception {
        logger.debug("OCSPJobResource.startJob(): jobId={}", jobId);
        Principal principal = securityContext.getUserPrincipal();
        createBase().startJob(jobId, principal);
        return Response.noContent().build();
    }
}
