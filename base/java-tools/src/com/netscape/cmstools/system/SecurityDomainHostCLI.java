//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.system.SecurityDomainClient;
import com.netscape.certsrv.system.SecurityDomainHost;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostCLI extends CLI {

    public SecurityDomainCLI parent;

    public SecurityDomainHostCLI(SecurityDomainCLI parent) {
        super("host", "Security domain host management commands", parent);
        this.parent = parent;

        addModule(new SecurityDomainHostFindCLI(this));
        addModule(new SecurityDomainHostShowCLI(this));
        addModule(new SecurityDomainHostAddCLI(this));
    }

    public SecurityDomainClient getSecurityDomainClient() throws Exception {
        return parent.getSecurityDomainClient();
    }

    public static void printSecurityDomainHost(SecurityDomainHost host) {

        System.out.println("  Host ID: " + host.getId());
        System.out.println("  Hostname: " + host.getHostname());
        System.out.println("  Port: " + host.getPort());
        System.out.println("  Secure Port: " + host.getSecurePort());

        if (host.getDomainManager() != null) {
            System.out.println("  Domain Manager: " + host.getDomainManager());
        }

        if (host.getClone() != null) {
            System.out.println("  Clone: " + host.getClone());
        }
    }
}
