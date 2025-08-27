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
public class ACMEDatabaseIndexCLI extends CLI {

    public ACMEDatabaseIndexCLI(CLI parent) {
        super("index", "ACME database index management commands", parent);

        addModule(new ACMEDatabaseIndexRebuildCLI(this));
    }
}
