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
public class ACMEDatabaseCLI extends CLI {

    public ACMEDatabaseCLI(CLI parent) {
        super("database", "ACME database management commands", parent);

        addModule(new ACMEDatabaseInitCLI(this));

        addModule(new ACMEDatabaseIndexCLI(this));
    }
}
