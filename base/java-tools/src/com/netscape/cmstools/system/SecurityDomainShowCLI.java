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

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.system.DomainInfo;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainShowCLI extends CLI {

    public SecurityDomainCLI securityDomainCLI;

    public SecurityDomainShowCLI(SecurityDomainCLI securityDomainCLI) {
        super("show", "Show domain info", securityDomainCLI);
        this.securityDomainCLI = securityDomainCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void execute(String[] args) throws Exception {

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

        DomainInfo domain = securityDomainCLI.securityDomainClient.getDomainInfo();

        SecurityDomainCLI.printSecurityDomain(domain);
    }
}
