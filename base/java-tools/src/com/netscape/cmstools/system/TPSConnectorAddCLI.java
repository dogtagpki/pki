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

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class TPSConnectorAddCLI extends CLI {
    public TPSConnectorCLI tpsConnectorCLI;

    public TPSConnectorAddCLI(TPSConnectorCLI tpsConnectorCLI) {
        super("add", "Add TPS Connector to TKS", tpsConnectorCLI);
        this.tpsConnectorCLI = tpsConnectorCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <TPS Host> <TPS Port>", options);
    }

    public void execute(String[] args) throws Exception {
        if (args.length != 2) {
            printHelp();
            System.exit(1);
        }

        String tpsHost = args[0];
        String tpsPort = args[1];

        tpsConnectorCLI.tpsConnectorClient.createConnector(tpsHost, tpsPort);

        MainCLI.printMessage("Added TPS connector \""+tpsHost + ":" + tpsPort +"\"");
    }

}
