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
public class SubsystemDBIndexCLI extends CLI {

    public SubsystemDBIndexCLI(CLI parent) {
        super("index", parent.parent.name.toUpperCase() + " index management commands", parent);

        addModule(new SubsystemDBIndexAddCLI(this));
        addModule(new SubsystemDBIndexRebuildCLI(this));
    }
}
