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

    public SubsystemCommandCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }
}
