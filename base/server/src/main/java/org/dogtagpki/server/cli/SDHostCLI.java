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
public class SDHostCLI extends CLI {

    public SDHostCLI(CLI parent) {
        super("host", "Security domain host management commands", parent);

        addModule(new SDHostAddCLI(this));
    }
}
