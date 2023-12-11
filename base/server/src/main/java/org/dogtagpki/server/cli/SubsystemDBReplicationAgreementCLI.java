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
public class SubsystemDBReplicationAgreementCLI extends CLI {

    public SubsystemDBReplicationAgreementCLI(CLI parent) {
        super(
            "agmt",
            parent.parent.parent.name.toUpperCase() + " replication agreement management commands",
            parent);

        addModule(new SubsystemDBReplicationAgreementInitCLI(this));
    }
}
