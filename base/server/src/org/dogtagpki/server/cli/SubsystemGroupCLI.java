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
public class SubsystemGroupCLI extends CLI {

    public SubsystemGroupCLI(CLI parent) {
        super("group", parent.name.toUpperCase() + " group management commands", parent);

        addModule(new SubsystemGroupFindCLI(this));
    }
}
