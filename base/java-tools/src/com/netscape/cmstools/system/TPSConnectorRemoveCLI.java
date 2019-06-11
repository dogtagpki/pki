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

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class TPSConnectorRemoveCLI extends CLI {
    public TPSConnectorCLI tpsConnectorCLI;

    public TPSConnectorRemoveCLI(TPSConnectorCLI tpsConnectorCLI) {
        super("del", "Remove TPS connector from TKS", tpsConnectorCLI);
        this.tpsConnectorCLI = tpsConnectorCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "host", true, "TPS host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "TPS port");
        option.setArgName("port");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String tpsHost = cmd.getOptionValue("host");
        String tpsPort = cmd.getOptionValue("port");

        TPSConnectorClient tpsConnectorClient = tpsConnectorCLI.getTPSConnectorClient();
        tpsConnectorClient.deleteConnector(tpsHost, tpsPort);

        MainCLI.printMessage("Removed TPS connector \""+tpsHost + ":" + tpsPort +"\"");
    }

}
