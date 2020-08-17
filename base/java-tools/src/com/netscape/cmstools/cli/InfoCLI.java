//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.common.Info;

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

        ClientConfig config = mainCLI.getConfig();
        System.out.println("  Server URL: " + config.getServerURL());

        PKIClient client = mainCLI.getClient();
        Info info = client.getInfo();
        if (info == null) return;

        String name = info.getName();
        if (!StringUtils.isEmpty(name)) {
            System.out.println("  Server Name: " + name);
        }

        String version = info.getVersion();
        if (!StringUtils.isEmpty(version)) {
            System.out.println("  Server Version: " + version);
        }
    }
}
