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

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AccountClient extends Client {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AccountClient.class);

    public boolean loggedIn;

    public AccountClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "account");
    }

    public AccountClient(PKIClient client, String subsystem, String prefix) throws Exception {
        super(client, subsystem, prefix, "account");
    }

    public Account login() throws Exception {
        Account account = get("login", Account.class);
        loggedIn = true;

        logger.info("Account:");
        logger.info("- ID: " + account.getID());
        logger.info("- Full Name: " + account.getFullName());
        logger.info("- Email: " + account.getEmail());

        logger.info("Roles:");
        for (String role : account.getRoles()) {
            logger.info("- " + role);
        }

        return account;
    }

    public void logout() throws Exception {
        if (!loggedIn) return;

        get("logout", Void.class);
        loggedIn = false;
    }
}
