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

import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainCLI extends CLI {

    public SecurityDomainClient securityDomainClient;

    public SecurityDomainCLI(CLI parent) {
        super("securitydomain", "Security domain commands", parent);

        addModule(new SecurityDomainGetInstallTokenCLI(this));
        addModule(new SecurityDomainShowCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();

        // determine the subsystem
        String subsystem = client.getSubsystem();
        if (subsystem == null) subsystem = "ca";

        // create new security domain client
        securityDomainClient = new SecurityDomainClient(client, subsystem);

        super.execute(args);
    }

    public static void printSecurityDomain(DomainInfo domain) {
        System.out.println("  Domain: " + domain.getName());
        System.out.println();

        for (SecurityDomainSubsystem subsystem : domain.getSubsystems()) {

            SecurityDomainHost[] hosts = subsystem.getHosts();
            if (hosts.length == 0) continue;

            System.out.println("  " + subsystem.getName() + " Subsystem:");
            System.out.println();

            for (SecurityDomainHost host : hosts) {
                System.out.println("    Host ID: " + host.getId());
                System.out.println("    Hostname: " + host.getHostname());
                System.out.println("    Port: " + host.getPort());
                System.out.println("    Secure Port: " + host.getSecurePort());
                if (host.getDomainManager() != null) System.out.println("    Domain Manager: " + host.getDomainManager());
                System.out.println();
            }
        }
    }
}
