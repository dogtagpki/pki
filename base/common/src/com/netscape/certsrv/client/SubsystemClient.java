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
package com.netscape.certsrv.client;

import java.net.URISyntaxException;

import com.netscape.certsrv.account.AccountClient;


/**
 * @author Endi S. Dewata
 */
public class SubsystemClient extends Client {

    public AccountClient accountClient;

    public SubsystemClient(PKIClient client, String name) throws URISyntaxException {
        // subsystem name should match the client name
        super(client, name, name);

        accountClient = new AccountClient(client, name);
        addClient(accountClient);
    }

    /**
     * Log in to the subsystem.
     */
    public void login() {
        accountClient.login();
    }

    /**
     * Log out from the subsystem.
     */
    public void logout() {
        accountClient.logout();
    }
}
