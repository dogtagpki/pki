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
public class SubsystemGroupMemberCLI extends CLI {

    public SubsystemGroupMemberCLI(CLI parent) {
        super("member", parent.name.toUpperCase() + " group member management commands", parent);

        addModule(new SubsystemGroupMemberFindCLI(this));
        addModule(new SubsystemGroupMemberAddCLI(this));
    }
}
