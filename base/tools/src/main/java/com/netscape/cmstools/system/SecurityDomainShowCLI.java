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
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainShowCLI extends CommandCLI {

    public SecurityDomainCLI securityDomainCLI;

    public SecurityDomainShowCLI(SecurityDomainCLI securityDomainCLI) {
        super("show", "Show domain info", securityDomainCLI);
        this.securityDomainCLI = securityDomainCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        SecurityDomainClient securityDomainClient = securityDomainCLI.getSecurityDomainClient();
        DomainInfo domain = securityDomainClient.getDomainInfo();

        SecurityDomainCLI.printSecurityDomain(domain);
    }
}
