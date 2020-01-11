//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;

public class InfoCLI extends CommandCLI {

    public InfoCLI(MainCLI mainCLI) {
        super("info", "Display server info", mainCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public String getFullName() {
        return name;
    }

    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        ClientConfig config = client.getConfig();
        InfoClient infoClient = new InfoClient(client);
        Info info = infoClient.getInfo();

        System.out.println("  Server: " + config.getServerURL());

        String name = info.getName();
        if (!StringUtils.isEmpty(name)) {
            System.out.println("  Name: " + name);
        }

        String version = info.getVersion();
        if (!StringUtils.isEmpty(version)) {
            System.out.println("  Version: " + version);
        }
    }
}
