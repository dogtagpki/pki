//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.system.SecurityDomainHost;

/**
 */
public class SDTypeCLI extends CLI {

    public SDTypeCLI(CLI parent) {
        super("type", "Security domain subsystem type management commands", parent);

        addModule(new SDTypeAddCLI(this));
    }
}
