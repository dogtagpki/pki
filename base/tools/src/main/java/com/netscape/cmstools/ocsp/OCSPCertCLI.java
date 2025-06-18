//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ocsp;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class OCSPCertCLI extends CLI {

    public OCSPCertCLI(CLI parent) {
        super("cert", "Certificate management commands", parent);

        addModule(new OCSPCertVerifyCLI(this));
    }
}
