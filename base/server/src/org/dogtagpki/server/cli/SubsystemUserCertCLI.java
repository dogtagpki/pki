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
public class SubsystemUserCertCLI extends CLI {

    public SubsystemUserCertCLI(CLI parent) {
        super("cert", parent.name.toUpperCase() + " user cert management commands", parent);

        addModule(new SubsystemUserCertAddCLI(this));
    }
}
