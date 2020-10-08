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
public class SubsystemRangeCLI extends CLI {

    public SubsystemRangeCLI(CLI parent) {
        super("range", parent.name.toUpperCase() + " range management commands", parent);

        addModule(new SubsystemRangeUpdateCLI(this));
    }
}
