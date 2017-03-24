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

package com.netscape.cmstools.cli;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.SubsystemClient;


/**
 * @author Endi S. Dewata
 */
public class SubsystemCLI extends CLI {

    public SubsystemCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    public String getFullName() {
        // do not include parent's name
        return name;
    }

    public SubsystemClient getSubsystemClient() throws Exception {
        return null;
    }

    public void login() throws Exception {
        SubsystemClient subsystemClient = getSubsystemClient();
        subsystemClient.login();
    }

    public void logout() throws Exception {
        SubsystemClient subsystemClient = getSubsystemClient();
        subsystemClient.logout();
    }

    public Client getClient(String name) throws Exception {
        SubsystemClient subsystemClient = getSubsystemClient();
        return subsystemClient.getClient(name);
    }

    public void execute(String[] args) throws Exception {

        // login if username or nickname is specified
        ClientConfig config = getConfig();
        if (config.getUsername() != null || config.getCertNickname() != null) {
            login();
        }

        super.execute(args);

        // logout if there is no failures
        if (config.getUsername() != null || config.getCertNickname() != null) {
            logout();
        }
    }
}
