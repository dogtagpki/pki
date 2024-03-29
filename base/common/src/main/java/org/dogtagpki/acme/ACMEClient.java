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
package org.dogtagpki.acme;

import java.net.URISyntaxException;

import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ACMEClient extends Client {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEClient.class);

    public ACMEClient(PKIClient client) throws URISyntaxException {
        super(client, "acme", null, null);
    }

    public Account login() throws Exception {
        Account account = post("login", Account.class);

        logger.info("Account: " + account.getID());

        logger.info("Roles:");
        for (String role : account.getRoles()) {
            logger.info("- " + role);
        }

        return account;
    }

    public void enable() throws Exception {
        post("enable", Void.class);
    }

    public void disable() throws Exception {
        post("disable", Void.class);
    }

    public void logout() throws Exception {
        post("logout", Void.class);
    }

    public ACMEDirectory getDirectory() throws Exception {
        return get("directory", ACMEDirectory.class);
    }
}
