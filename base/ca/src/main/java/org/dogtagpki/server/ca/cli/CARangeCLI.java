//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class CARangeCLI extends CLI {

    public CARangeCLI(CLI parent) {
        super("range", "CA range management commands", parent);

        addModule(new CARangeUpdateCLI(this));
    }
}
