//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.EBaseException;

/**
 * @author Endi S. Dewata
 */
@Path("jobs")
public interface JobResource {

    @POST
    public Response startJob(String id) throws EBaseException;
}
