//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.base.EBaseException;

/**
 * @author Endi S. Dewata
 */
@Path("jobs")
public interface JobResource {

    /**
     * Returns all jobs.
     *
     * If the method is executed by an admin, it will return all jobs.
     * Otherwise, it will return all jobs owned by the user.
     */
    @GET
    public Response findJobs() throws EBaseException;

    /**
     * Returns a specific job.
     *
     * This method can only be executed by an admin or the job owner.
     */
    @GET
    @Path("{id}")
    public Response getJob(@PathParam("id") String id) throws EBaseException;

    /**
     * Starts a specific job.
     *
     * This method can only be executed by an admin or the job owner.
     */
    @POST
    @Path("{id}/start")
    public Response startJob(@PathParam("id") String id) throws EBaseException;
}
