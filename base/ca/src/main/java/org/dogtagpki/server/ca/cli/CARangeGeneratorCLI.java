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
public class CARangeGeneratorCLI extends CLI{

    public CARangeGeneratorCLI(CLI parent) {
        super("generator", "CA range generator commands", parent);

        addModule(new CARangeGeneratorUpdateCLI(this));
    }
    
}
