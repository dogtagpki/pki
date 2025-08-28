//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

/**
 */
public class SubsystemACLCLI extends CLI {

    public SubsystemACLCLI(CLI parent) {
        super("acl", parent.name.toUpperCase() + " ACL management commands", parent);

        addModule(new SubsystemACLFindCLI(this));
        addModule(new SubsystemACLAddCLI(this));
        addModule(new SubsystemACLDeleteCLI(this));
    }
}
