//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemDBAccessCLI;
import org.dogtagpki.server.cli.SubsystemDBCreateCLI;
import org.dogtagpki.server.cli.SubsystemDBEmptyCLI;
import org.dogtagpki.server.cli.SubsystemDBIndexCLI;
import org.dogtagpki.server.cli.SubsystemDBInfoCLI;
import org.dogtagpki.server.cli.SubsystemDBRemoveCLI;
import org.dogtagpki.server.cli.SubsystemDBReplicationCLI;
import org.dogtagpki.server.cli.SubsystemDBUpgradeCLI;
import org.dogtagpki.server.cli.SubsystemDBVLVCLI;

/**
 * @author Endi S. Dewata
 */
public class KRADBCLI extends CLI {

    public KRADBCLI(CLI parent) {
        super("db", "KRA database management commands", parent);

        addModule(new SubsystemDBInfoCLI(this));
        addModule(new SubsystemDBCreateCLI(this));
        addModule(new KRADBInitCLI(this));
        addModule(new SubsystemDBEmptyCLI(this));
        addModule(new SubsystemDBRemoveCLI(this));
        addModule(new SubsystemDBUpgradeCLI(this));

        addModule(new SubsystemDBAccessCLI(this));
        addModule(new SubsystemDBIndexCLI(this));
        addModule(new SubsystemDBReplicationCLI(this));
        addModule(new SubsystemDBVLVCLI(this));
    }
}
