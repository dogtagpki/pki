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
public class OCSPCRLIssuingPointCLI extends CLI {

    public OCSPCRLIssuingPointCLI(CLI parent) {
        super("issuingpoint", "OCSP CRL issuing point management commands", parent);

        addModule(new OCSPCRLIssuingPointFindCLI(this));
    }
}
