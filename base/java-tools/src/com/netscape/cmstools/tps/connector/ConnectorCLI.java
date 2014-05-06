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

package com.netscape.cmstools.tps.connector;

import java.io.IOException;
import java.util.Map;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.certsrv.tps.connector.ConnectorClient;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ConnectorCLI extends CLI {

    public ConnectorClient connectorClient;

    public ConnectorCLI(CLI parent) {
        super("connector", "Connector management commands", parent);

        addModule(new ConnectorAddCLI(this));
        addModule(new ConnectorFindCLI(this));
        addModule(new ConnectorModifyCLI(this));
        addModule(new ConnectorRemoveCLI(this));
        addModule(new ConnectorShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        connectorClient = (ConnectorClient)parent.getClient("connector");

        super.execute(args);
    }

    public static void printConnectorData(ConnectorData connectorData, boolean showProperties) throws IOException {
        System.out.println("  Connector ID: " + connectorData.getID());
        if (connectorData.getStatus() != null) System.out.println("  Status: " + connectorData.getStatus());

        if (showProperties) {
            System.out.println("  Properties:");
            Map<String, String> properties = connectorData.getProperties();
            if (properties != null) {
                for (String name : properties.keySet()) {
                    String value = properties.get(name);
                    System.out.println("    " + name + ": " + value);
                }
            }
        }

        Link link = connectorData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
