//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemRangeUpdateCLI;

/**
 * @author Endi S. Dewata
 */
public class KRARangeCLI extends CLI {

    public KRARangeCLI(CLI parent) {
        super("range", "KRA range management commands", parent);

        addModule(new SubsystemRangeUpdateCLI(this));
    }
}
