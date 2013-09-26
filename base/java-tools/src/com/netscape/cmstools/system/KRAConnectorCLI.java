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
package com.netscape.cmstools.system;

import com.netscape.certsrv.system.KRAConnectorClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorCLI extends CLI {

    public KRAConnectorClient kraConnectorClient;

    public KRAConnectorCLI(CLI parent) {
        super("kraconnector", "KRA Connector management commands", parent);

        addModule(new KRAConnectorAddCLI(this));
        addModule(new KRAConnectorRemoveCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();

        // determine the subsystem
        String subsystem = client.getSubsystem();
        if (subsystem == null) subsystem = "ca";

        // create new KRA connector client
        kraConnectorClient = new KRAConnectorClient(client, subsystem);

        super.execute(args);
    }
}
