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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.acme;

import java.net.URI;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEDirectory;

@Path("directory")
public class ACMEDirectoryService {

    @Context
    UriInfo uriInfo;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public ACMEDirectory getDirectory() {

        ACMEDirectory directory = new ACMEDirectory();

        URI newNonce = uriInfo.getBaseUriBuilder().path("new-nonce").build();
        directory.setNewNonce(newNonce);

        URI newAccount = uriInfo.getBaseUriBuilder().path("new-account").build();
        directory.setNewAccount(newAccount);

        URI newOrder = uriInfo.getBaseUriBuilder().path("new-order").build();
        directory.setNewOrder(newOrder);

        URI newAuthz = uriInfo.getBaseUriBuilder().path("new-authz").build();
        directory.setNewAuthz(newAuthz);

        URI revokeCert = uriInfo.getBaseUriBuilder().path("revoke-cert").build();
        directory.setRevokeCert(revokeCert);

        URI keyChange = uriInfo.getBaseUriBuilder().path("key-change").build();
        directory.setKeyChange(keyChange);

        return directory;
    }
}
