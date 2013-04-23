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

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AccountClient {

    public PKIClient client;
    public AccountResource resource;

    public AccountClient(ClientConfig config) throws URISyntaxException {
        this(new PKIClient(config));
    }

    public AccountClient(PKIClient client) throws URISyntaxException {
        this.client = client;
        init();
    }

    public void init() throws URISyntaxException {
        resource = client.createProxy(AccountResource.class);
    }

    public void login() {
        resource.login();
    }

    public void logout() {
        resource.logout();
    }
}
