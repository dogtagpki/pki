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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.account;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

/**
 * @author Endi S. Dewata
 */
@Path("account")
@AuthMethodMapping("account")
public interface AccountResource {

    @GET
    @Path("login")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("account.login")
    public Response login();

    @GET
    @Path("logout")
    @ClientResponseType(entityType=Void.class)
    @ACLMapping("account.logout")
    public Response logout();
}
