//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.system;

import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;

/**
 * @author Endi S. Dewata
 */
@Path("securityDomain/hosts")
public interface SecurityDomainHostResource {

    @GET
    public Response getHosts() throws Exception;

    @GET
    @Path("{hostID}")
    public Response getHost(@PathParam("hostID") String hostID) throws Exception;

    @PUT
    @ACLMapping("securityDomain.modify")
    public Response addHost(SecurityDomainHost host) throws Exception;
}
