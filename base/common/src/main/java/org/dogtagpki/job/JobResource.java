//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.EBaseException;

/**
 * @author Endi S. Dewata
 */
@Path("jobs")
@RolesAllowed("Administrators")
public interface JobResource {

    @GET
    public Response findJobs() throws EBaseException;

    @POST
    public Response startJob(String id) throws EBaseException;
}
