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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.KRAConnectorClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorRemoveCLI extends SubsystemCommandCLI {

    public KRAConnectorCLI kraConnectorCLI;

    public KRAConnectorRemoveCLI(KRAConnectorCLI kraConnectorCLI) {
        super("del", "Remove KRA connector from CA", kraConnectorCLI);
        this.kraConnectorCLI = kraConnectorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "host", true, "KRA host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "KRA port");
        option.setArgName("port");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        String kraHost = cmd.getOptionValue("host");
        String kraPort = cmd.getOptionValue("port");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        KRAConnectorClient kraConnectorClient = kraConnectorCLI.getKRAConnectorClient(client);
        kraConnectorClient.removeConnector(kraHost, kraPort);

        MainCLI.printMessage("Removed KRA host \"" + kraHost + ":" + kraPort + "\"");
    }
}
