//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class KRARangeCLI extends CLI {

    public KRARangeCLI(CLI parent) {
        super("range", "KRA range management commands", parent);

        addModule(new KRARangeUpdateCLI(this));
    }
}
