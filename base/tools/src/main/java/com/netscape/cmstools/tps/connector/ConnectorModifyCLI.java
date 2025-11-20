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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.connector.ConnectorClient;
import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class ConnectorModifyCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConnectorModifyCLI.class);

    public ConnectorCLI connectorCLI;

    public ConnectorModifyCLI(ConnectorCLI connectorCLI) {
        super("mod", "Modify connector", connectorCLI);
        this.connectorCLI = connectorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Connector ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "action", true, "Action: update (default), approve, reject, enable, disable.");
        option.setArgName("action");
        options.addOption(option);

        option = new Option(null, "input", true, "Input file containing connector properties.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Connector ID specified.");
        }

        String connectorID = cmdArgs[0];
        String action = cmd.getOptionValue("action", "update");
        String input = cmd.getOptionValue("input");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = connectorCLI.tpsCLI.getSubsystemClient(client);
        ConnectorClient connectorClient = new ConnectorClient(subsystemClient);
        ConnectorData connectorData;

        if (action.equals("update")) {

            if (input == null) {
                throw new Exception("Missing input file");
            }

            try (BufferedReader in = new BufferedReader(new FileReader(input));
                StringWriter sw = new StringWriter();
                PrintWriter out = new PrintWriter(sw, true)) {

                String line;
                while ((line = in.readLine()) != null) {
                    out.println(line);
                }

                connectorData = JSONSerializer.fromJSON(sw.toString(), ConnectorData.class);
            }

            connectorData = connectorClient.updateConnector(connectorID, connectorData);

        } else { // other actions
            connectorData = connectorClient.changeConnectorStatus(connectorID, action);
        }

        MainCLI.printMessage("Modified connector \"" + connectorID + "\"");

        ConnectorCLI.printConnectorData(connectorData, true);
    }
}
