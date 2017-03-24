package com.netscape.cmstools.system;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.system.TPSConnectorClient;
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
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Connector ID specified.");
        }

        String connID = cmdArgs[0];

        TPSConnectorData data = new TPSConnectorData();
        data.setID(connID);

        // NOTE: neither nickname nor userid can be set using this interface
        data.setHost(cmd.getOptionValue("host"));
        data.setPort(cmd.getOptionValue("port"));

        TPSConnectorClient tpsConnectorClient = tpsConnectorCLI.getTPSConnectorClient();
        data = tpsConnectorClient.modifyConnector(connID, data);

        MainCLI.printMessage("Modified TPS connector \""+connID +"\"");

        TPSConnectorCLI.printConnectorInfo(data);
    }

}
