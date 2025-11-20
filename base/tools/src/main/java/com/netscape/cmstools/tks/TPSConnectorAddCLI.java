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
package com.netscape.cmstools.tks;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Ade Lee
 */
public class TPSConnectorAddCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSConnectorAddCLI.class);

    public TPSConnectorCLI tpsConnectorCLI;

    public TPSConnectorAddCLI(TPSConnectorCLI tpsConnectorCLI) {
        super("add", "Add TPS connector to TKS", tpsConnectorCLI);
        this.tpsConnectorCLI = tpsConnectorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "host", true, "TPS host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "TPS port");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String tpsHost = cmd.getOptionValue("host");
        String tpsPort = cmd.getOptionValue("port");
        String outputFormat = cmd.getOptionValue("output-format", "text");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = tpsConnectorCLI.tksCLI.getSubsystemClient(client);
        TPSConnectorClient tpsConnectorClient = new TPSConnectorClient(subsystemClient);
        TPSConnectorData data = tpsConnectorClient.createConnector(tpsHost, tpsPort);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(data.toJSON());

        } else {
            MainCLI.printMessage("Added TPS connector \""+tpsHost + ":" + tpsPort +"\"");
        }
    }

}
