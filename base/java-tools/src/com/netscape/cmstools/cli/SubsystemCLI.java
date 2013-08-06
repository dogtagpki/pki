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

import com.netscape.certsrv.client.ClientConfig;


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

    public void init() throws Exception {
    }

    public void login() throws Exception {
    }

    public void logout() throws Exception {
    }

    public void execute(String[] args) throws Exception {

        init();

        try {
            // login if username or nickname is specified
            ClientConfig config = getClient().getConfig();
            if (config.getUsername() != null || config.getCertNickname() != null) {
                login();
            }

            super.execute(args);

        } finally {
            logout();
        }
    }
}
