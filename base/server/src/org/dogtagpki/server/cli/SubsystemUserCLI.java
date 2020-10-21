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
public class SubsystemUserCLI extends CLI {

    public SubsystemUserCLI(CLI parent) {
        super("user", parent.name.toUpperCase() + " user management commands", parent);

        addModule(new SubsystemUserFindCLI(this));
        addModule(new SubsystemUserModifyCLI(this));
    }
}
