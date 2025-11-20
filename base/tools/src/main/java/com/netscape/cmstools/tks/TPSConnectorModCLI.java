package com.netscape.cmstools.tks;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class TPSConnectorModCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSConnectorModCLI.class);

    public TPSConnectorCLI tpsConnectorCLI;

    public TPSConnectorModCLI(TPSConnectorCLI tpsConnectorCLI) {
        super("mod", "Modify TPS connector on TKS", tpsConnectorCLI);
        this.tpsConnectorCLI = tpsConnectorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Connector ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "host", true, "TPS host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "TPS port");
        option.setArgName("port");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = tpsConnectorCLI.tksCLI.getSubsystemClient(client);
        TPSConnectorClient tpsConnectorClient = new TPSConnectorClient(subsystemClient);
        data = tpsConnectorClient.modifyConnector(connID, data);

        MainCLI.printMessage("Modified TPS connector \""+connID +"\"");

        TPSConnectorCLI.printConnectorInfo(data);
    }

}
