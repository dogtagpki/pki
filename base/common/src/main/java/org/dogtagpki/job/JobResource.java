//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

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
    public Response startJob(String id) throws EBaseException;
}
