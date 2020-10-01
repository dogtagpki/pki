//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostFindCLI extends CommandCLI {

    public SecurityDomainHostCLI securityDomainHostCLI;

    public SecurityDomainHostFindCLI(SecurityDomainHostCLI securityDomainHostCLI) {
        super("find", "Find security domain hosts", securityDomainHostCLI);
        this.securityDomainHostCLI = securityDomainHostCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        SecurityDomainClient securityDomainClient = securityDomainHostCLI.getSecurityDomainClient();
        Collection<SecurityDomainHost> hosts = securityDomainClient.getHosts();
        boolean first = true;

        for (SecurityDomainHost host : hosts) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            SecurityDomainHostCLI.printSecurityDomainHost(host);
        }
    }
}
