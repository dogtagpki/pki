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
public class CACRLRecordCLI extends CLI {

    public CACRLRecordCLI(CLI parent) {
        super("record", "CRL record management commands", parent);

        addModule(new CACRLRecordShowCLI(this));
    }
}
