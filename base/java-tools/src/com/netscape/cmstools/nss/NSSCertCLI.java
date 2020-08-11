//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;

public class NSSCertCLI extends CLI {

    public NSSCertCLI(NSSCLI nssCLI) {
        super("cert", "NSS certificate management commands", nssCLI);

        addModule(new NSSCertExportCLI(this));
        addModule(new NSSCertImportCLI(this));
        addModule(new NSSCertIssueCLI(this));
        addModule(new NSSCertRequestCLI(this));
    }
}
