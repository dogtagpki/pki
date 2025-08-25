//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.acme.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ACMECLI extends CLI {

    public ACMECLI(CLI parent) {
        super("acme", "ACME subsystem management commands", parent);

        addModule(new ACMEDatabaseCLI(this));
    }
}
