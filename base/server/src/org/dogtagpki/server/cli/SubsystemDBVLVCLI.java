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
public class SubsystemDBVLVCLI extends CLI {

    public SubsystemDBVLVCLI(CLI parent) {
        super("vlv", parent.parent.name.toUpperCase() + " VLV management commands", parent);

        addModule(new SubsystemDBVLVFindCLI(this));
    }
}
