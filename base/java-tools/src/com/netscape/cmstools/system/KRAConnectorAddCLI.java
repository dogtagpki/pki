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

import java.io.FileInputStream;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.system.ConnectorNotFoundException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorAddCLI extends CLI {

    public KRAConnectorCLI kraConnectorCLI;

    public KRAConnectorAddCLI(KRAConnectorCLI kraConnectorCLI) {
        super("add", "Add KRA Connector", kraConnectorCLI);
        this.kraConnectorCLI = kraConnectorCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(
                getFullName() + " --input-file <file> | --host <KRA host> --port <KRA port>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "host", true, "KRA host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "KRA port");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "input-file", true, "Input file");
        option.setArgName("input-file");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        String kraHost = cmd.getOptionValue("host");
        String kraPort = cmd.getOptionValue("port");
        String inputFile = cmd.getOptionValue("input-file");

        //check if connector exists
        boolean connectorExists = true;
        try {
            @SuppressWarnings("unused")
            KRAConnectorInfo info = kraConnectorCLI.kraConnectorClient.getConnectorInfo();
        } catch (ConnectorNotFoundException e) {
            connectorExists = false;
        }

        if (inputFile != null) {
            if (connectorExists) {
                System.err.println("Error: Cannot add new connector from file.  " +
                        "Delete the existing connector first");
                System.exit(-1);
            }
            FileInputStream fis = new FileInputStream(inputFile);
            JAXBContext context = JAXBContext.newInstance(KRAConnectorInfo.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            KRAConnectorInfo info = (KRAConnectorInfo) unmarshaller.unmarshal(fis);

            kraConnectorCLI.kraConnectorClient.addConnector(info);
            MainCLI.printMessage("Added KRA connector");

        } else {
            if (!connectorExists) {
                System.err.println("Error: Cannot add new host to existing connector.  " +
                        "No connector currently exists");
                System.exit(-1);
            }
            kraConnectorCLI.kraConnectorClient.addHost(kraHost, kraPort);
            MainCLI.printMessage("Added KRA host \"" + kraHost + ":" + kraPort + "\"");
        }
    }
}
