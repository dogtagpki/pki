//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.acme;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ACMECLI extends CLI {

    public ACMECLI(MainCLI mainCLI) {
        super("acme", "ACME management commands", mainCLI);

        addModule(new ACMEInfoCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }
}
