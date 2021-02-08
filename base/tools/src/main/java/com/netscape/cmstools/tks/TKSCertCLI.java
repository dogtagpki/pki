//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class TKSCertCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSCertCLI.class);

    public TKSCLI tksCLI;

    public TKSCertCLI(TKSCLI tksCLI) {
        super("cert", "TKS certificate management commands", tksCLI);
        this.tksCLI = tksCLI;

        addModule(new TKSCertTransportImportCLI(this));
    }
}
