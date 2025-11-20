//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;

/**
 * This class represents a CLI command that will access a PKI subsystem.
 *
 * @author Endi S. Dewata
 */
public class SubsystemCommandCLI extends CommandCLI {

    public SubsystemCLI subsystemCLI;

    public SubsystemCommandCLI(String name, String description, CLI parent) {
        super(name, description, parent);

        // find subsystem CLI object in CLI hierarchy
        CLI cli = parent;
        while (cli != null) {
            if (cli instanceof SubsystemCLI subsystemCLI) {
                // found subsystem CLI object
                this.subsystemCLI = subsystemCLI;
                break;
            } else {
                // keep looking
                cli = cli.parent;
            }
        }
    }
}
