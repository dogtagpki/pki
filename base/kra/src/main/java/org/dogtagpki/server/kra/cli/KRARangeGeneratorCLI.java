//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;
/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class KRARangeGeneratorCLI extends CLI {
    public KRARangeGeneratorCLI(CLI parent) {
        super("generator", "kra range generator commands", parent);

        addModule(new kraRangeGeneratorUpdateCLI(this));
    }
}
