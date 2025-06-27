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
public class CACRLCLI extends CLI {

    public CACRLCLI(CLI parent) {
        super("crl", "CRL management commands", parent);

        addModule(new CACRLRecordCLI(this));
    }
}
