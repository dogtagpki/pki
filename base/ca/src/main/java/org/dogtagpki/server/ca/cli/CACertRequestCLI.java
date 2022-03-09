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
public class CACertRequestCLI extends CLI {

    public CACertRequestCLI(CLI parent) {
        super("request", "CA certificate request management commands", parent);

        addModule(new CACertRequestImportCLI(this));
    }
}
