//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class SDSubsystemCLI extends CLI {

    public SDSubsystemCLI(CLI parent) {
        super("subsystem", "Security domain subsystem management commands", parent);

        addModule(new SDSubsystemAddCLI(this));
    }
}
