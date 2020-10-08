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
public class CACertCLI extends CLI {

    public CACertCLI(CLI parent) {
        super("cert", "CA certificate management commands", parent);

        addModule(new CACertRemoveCLI(this));
    }
}
