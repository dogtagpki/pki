package com.netscape.cmstools.system;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.system.KRAConnectorClient;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cmstools.cli.MainCLI;

public class KRAConnectorShowCLI extends CommandCLI {

    public KRAConnectorCLI kraConnectorCLI;

    public KRAConnectorShowCLI(KRAConnectorCLI kraConnectorCLI) {
        super("show", "Show KRA Connector", kraConnectorCLI);
        this.kraConnectorCLI = kraConnectorCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        KRAConnectorClient kraConnectorClient = kraConnectorCLI.getKRAConnectorClient();
        KRAConnectorInfo info = kraConnectorClient.getConnectorInfo();

        // Print the KRA Connector Information.

        System.out.println();
        String host = info.getHost().trim();
        if (host.indexOf(' ') == -1) {
            host += ":" + info.getPort();
        } else {
            // Assuming that the configuration file is not corrupted.
            host.replace(" ", ", ");
        }
        System.out.println("Host: " + host);
        System.out.println("Enabled: " + info.getEnable());
        System.out.println("Local: " + info.getLocal());
        System.out.println("Timeout: " + info.getTimeout());
        System.out.println("URI: " + info.getUri());
        System.out.println("Transport Cert: \n");
        String transportCert = info.getTransportCert();
        int i = 0;
        for (i = 0; i < transportCert.length() / 64; i++) {
            System.out.println(transportCert.substring(i * 64, (i * 64) + 64));
        }
        System.out.println(transportCert.substring(i * 64));
        System.out.println();
    }
}
