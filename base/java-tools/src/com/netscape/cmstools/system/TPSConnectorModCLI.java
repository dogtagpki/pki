package com.netscape.cmstools.system;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class TPSConnectorModCLI extends CLI {
    public TPSConnectorCLI tpsConnectorCLI;

    public TPSConnectorModCLI(TPSConnectorCLI tpsConnectorCLI) {
        super("mod", "Modify TPS connector on TKS", tpsConnectorCLI);
        this.tpsConnectorCLI = tpsConnectorCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Connector ID> [OPTIONS...]", options);
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
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: No Connector ID specified.");
            printHelp();
            System.exit(-1);
        }

        String connID = cmdArgs[0];

        TPSConnectorData data = new TPSConnectorData();
        data.setID(connID);

        // NOTE: neither nickname nor userid can be set using this interface
        data.setHost(cmd.getOptionValue("host"));
        data.setPort(cmd.getOptionValue("port"));

        data = tpsConnectorCLI.tpsConnectorClient.modifyConnector(connID, data);

        MainCLI.printMessage("Modified TPS connector \""+connID +"\"");

        TPSConnectorCLI.printConnectorInfo(data);
    }

}
