//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostAddCLI extends CommandCLI {

    public SecurityDomainHostCLI securityDomainHostCLI;

    public SecurityDomainHostAddCLI(SecurityDomainHostCLI securityDomainHostCLI) {
        super("add", "Add security domain host", securityDomainHostCLI);
        this.securityDomainHostCLI = securityDomainHostCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <Host ID>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "port", true, "Port (default: 8080)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "securePort", true, "Secure port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "domainManager", true, "Domain manager (default: FALSE)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "clone", true, "Clone (default: FALSE)");
        option.setArgName("boolean");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing host ID");
        }

        String hostID = cmdArgs[0];

        SecurityDomainHost host = new SecurityDomainHost();
        host.setId(hostID);

        String port = cmd.getOptionValue("port", "8080");
        host.setPort(port);

        String securePort = cmd.getOptionValue("securePort", "8443");
        host.setSecureEEClientAuthPort(securePort);
        host.setSecureAdminPort(securePort);
        host.setSecureAgentPort(securePort);

        String domainManager = cmd.getOptionValue("domainManager", "FALSE");
        host.setDomainManager(domainManager);

        String clone = cmd.getOptionValue("clone", "FALSE");
        host.setClone(clone);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        SecurityDomainClient securityDomainClient = securityDomainHostCLI.getSecurityDomainClient();
        securityDomainClient.addHost(host);
    }
}
