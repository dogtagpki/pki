//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class CAIdCLI extends CLI {
    public CAIdCLI(CLI parent) {
        super("id", "CA id generator management commands", parent);

        addModule(new CAIdGeneratorCLI(this));
    }
}
