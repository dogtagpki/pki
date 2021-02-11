//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class OCSPCRLCLI extends CLI {

    public OCSPCRLCLI(CLI parent) {
        super("crl", "OCSP CRL management commands", parent);

        addModule(new OCSPCRLIssuingPointCLI(this));
    }
}
