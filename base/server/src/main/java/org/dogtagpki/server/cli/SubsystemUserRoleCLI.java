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
public class SubsystemUserRoleCLI extends CLI {

    public SubsystemUserRoleCLI(CLI parent) {
        super("role", parent.name.toUpperCase() + " user role management commands", parent);

        addModule(new SubsystemUserRoleFindCLI(this));
    }
}
