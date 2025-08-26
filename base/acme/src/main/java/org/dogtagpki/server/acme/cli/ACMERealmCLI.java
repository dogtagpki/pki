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
public class ACMERealmCLI extends CLI {

    public ACMERealmCLI(CLI parent) {
        super("realm", "ACME realm management commands", parent);

        addModule(new ACMERealmInitCLI(this));
    }
}
