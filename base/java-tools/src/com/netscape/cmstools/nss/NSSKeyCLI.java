//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;

public class NSSKeyCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSKeyCLI.class);

    public NSSCLI nssCLI;

    public NSSKeyCLI(NSSCLI tksCLI) {
        super("key", "NSS key management commands", tksCLI);
        this.nssCLI = tksCLI;

        addModule(new NSSKeyExportCLI(this));
        addModule(new NSSKeyImportCLI(this));
    }

    public String getFullName() {
        return parent.getFullName() + "-" + name;
    }
}
