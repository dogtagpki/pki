//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;

public class NSSKeyCLI extends CLI {

    public NSSKeyCLI(NSSCLI nssCLI) {
        super("key", "NSS key management commands", nssCLI);

        addModule(new NSSKeyExportCLI(this));
        addModule(new NSSKeyImportCLI(this));
    }
}
