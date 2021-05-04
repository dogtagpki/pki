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
public class SDCLI extends CLI {

    public SDCLI(CLI parent) {
        super("sd", "Security domain management commands", parent);

        addModule(new SDCreateCLI(this));
        addModule(new SDHostCLI(this));
    }
}
