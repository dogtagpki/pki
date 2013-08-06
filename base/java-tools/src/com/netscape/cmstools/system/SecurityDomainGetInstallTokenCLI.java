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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.system;

import java.net.InetAddress;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.system.InstallToken;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainGetInstallTokenCLI extends CLI {

    public SecurityDomainCLI securityDomainCLI;

    public SecurityDomainGetInstallTokenCLI(SecurityDomainCLI securityDomainCLI) {
        super("get-install-token", "Get install token", securityDomainCLI);
        this.securityDomainCLI = securityDomainCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "hostname", true, "Hostname");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option(null, "subsystem", true, "Subsystem");
        option.setArgName("subsystem");
        option.setRequired(true);
        options.addOption(option);

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            printHelp();
            System.exit(1);
        }

        String hostname = cmd.getOptionValue("hostname");
        if (hostname == null) {
            hostname = InetAddress.getLocalHost().getHostName();
        }

        String subsystem = cmd.getOptionValue("subsystem");

        InstallToken token = securityDomainCLI.securityDomainClient.getInstallToken(hostname, subsystem);

        MainCLI.printMessage("Install token: \"" + token.getToken() + "\"");
    }
}
