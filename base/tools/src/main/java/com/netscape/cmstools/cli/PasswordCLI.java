//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import org.dogtagpki.cli.CLI;

public class PasswordCLI extends CLI {

    public PasswordCLI(CLI parent) {
        super("password", "Password utilities", parent);

        addModule(new PasswordGenerateCLI(this));
    }

    @Override
    public String getFullName() {
        // do not include MainCLI's name
        return parent instanceof MainCLI ? name : parent.getFullName() + "-" + name;
    }
}
