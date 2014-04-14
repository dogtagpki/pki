//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.account;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AccountClient extends Client {

    public AccountResource resource;
    public boolean loggedIn;

    public AccountClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "account");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(AccountResource.class);
    }

    public AccountInfo login() {
        Response response = resource.login();
        AccountInfo info = client.getEntity(response, AccountInfo.class);
        loggedIn = true;

        if (client.verbose) {
            System.out.println("Account:");
            System.out.println(" - User ID: " + info.getID());
            System.out.println(" - Full Name: " + info.getFullName());
            System.out.println(" - Email: " + info.getEmail());
            System.out.println(" - Roles: " + info.getRoles());
        }

        return info;
    }

    public void logout() {
        if (!loggedIn) return;

        Response response = resource.logout();
        client.getEntity(response, Void.class);
        loggedIn = false;
    }
}
