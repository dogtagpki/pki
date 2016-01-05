// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.selftests;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;


/**
 * @author Endi S. Dewata
 */
@Path("selftests")
@AuthMethodMapping("selftests")
@ACLMapping("selftests.read")
public interface SelfTestResource {

    @GET
    @ClientResponseType(entityType=SelfTestCollection.class)
    public Response findSelfTests(
            @QueryParam("filter") String filter,
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size);

    @POST
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("selftests.execute")
    public Response executeSelfTests(@QueryParam("action") String action);

    @POST
    @Path("run")
    @ClientResponseType(entityType=SelfTestResults.class)
    @ACLMapping("selftests.execute")
    public Response runSelfTests();

    @GET
    @Path("{selfTestID}")
    @ClientResponseType(entityType=SelfTestData.class)
    public Response getSelfTest(@PathParam("selfTestID") String selfTestID);

    @POST
    @Path("{selfTestID}/run")
    @ClientResponseType(entityType=SelfTestResult.class)
    @ACLMapping("selftests.execute")
    public Response runSelfTest(@PathParam("selfTestID") String selfTestID);
}
