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
public class CAIdGeneratorCLI extends CLI {

    public CAIdGeneratorCLI(CLI parent) {
        super("generator", "CA id generator commands", parent);

        addModule(new CAIdGeneratorUpdateCLI(this));
    }

}