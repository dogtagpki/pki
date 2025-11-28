//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostRemoveCLI extends CommandCLI {

    public SecurityDomainHostCLI securityDomainHostCLI;

    public SecurityDomainHostRemoveCLI(SecurityDomainHostCLI securityDomainHostCLI) {
        super("del", "Remove security domain host", securityDomainHostCLI);
        this.securityDomainHostCLI = securityDomainHostCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Host ID>", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing host ID");
        }

        String hostID = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getPKIClient();
        SecurityDomainClient securityDomainClient = securityDomainHostCLI.getSecurityDomainClient(client);
        securityDomainClient.removeHost(hostID);
    }
}
