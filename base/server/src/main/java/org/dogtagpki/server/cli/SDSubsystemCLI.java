//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.system.SecurityDomainHost;

/**
 * @author Endi S. Dewata
 */
public class SDSubsystemCLI extends CLI {

    public SDSubsystemCLI(CLI parent) {
        super("subsystem", "Security domain subsystem management commands", parent);

        addModule(new SDSubsystemFindCLI(this));
        addModule(new SDSubsystemAddCLI(this));
        addModule(new SDSubsystemRemoveCLI(this));
    }

    public static void printSubsystem(SecurityDomainHost host) {

        System.out.println("  Subsystem ID: " + host.getId());
        System.out.println("  Hostname: " + host.getHostname());

        String port = host.getPort();
        if (port != null) {
            System.out.println("  Port: " + port);
        }

        System.out.println("  Secure Port: " + host.getSecurePort());

        if (host.getDomainManager() != null) {
            System.out.println("  Domain Manager: " + host.getDomainManager());
        }

        if (host.getClone() != null) {
            System.out.println("  Clone: " + host.getClone());
        }
    }
}
