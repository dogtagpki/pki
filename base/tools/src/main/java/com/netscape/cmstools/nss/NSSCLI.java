//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class NSSCLI extends CLI {

    public MainCLI mainCLI;

    public NSSCLI(MainCLI mainCLI) {
        super("nss", "NSS management commands", mainCLI);
        this.mainCLI = mainCLI;

        addModule(new NSSCreateCLI(this));
        addModule(new NSSRemoveCLI(this));

        addModule(new NSSCertCLI(this));
        addModule(new NSSKeyCLI(this));
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
