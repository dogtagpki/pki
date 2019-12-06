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

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.KRAConnectorClient;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorCLI extends CLI {

    public CACLI caCLI;
    public KRAConnectorClient kraConnectorClient;

    public KRAConnectorCLI(CACLI caCLI) {
        super("kraconnector", "KRA Connector management commands", caCLI);
        this.caCLI = caCLI;

        addModule(new KRAConnectorAddCLI(this));
        addModule(new KRAConnectorRemoveCLI(this));
        addModule(new KRAConnectorShowCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public KRAConnectorClient getKRAConnectorClient() throws Exception {

        if (kraConnectorClient != null) return kraConnectorClient;

        PKIClient client = getClient();

        // determine the subsystem
        String subsystem = client.getSubsystem();
        if (subsystem == null) subsystem = "ca";

        // create new KRA connector client
        kraConnectorClient = new KRAConnectorClient(client, subsystem);

        return kraConnectorClient;
    }
}
