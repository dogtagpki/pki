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
public class SubsystemDBAccessCLI extends CLI {

    public SubsystemDBAccessCLI(CLI parent) {
        super("access", parent.parent.name.toUpperCase() + " database access managerment commands", parent);

        addModule(new SubsystemDBAccessGrantCLI(this));
        addModule(new SubsystemDBAccessRevokeCLI(this));
    }
}
