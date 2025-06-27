//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class CACRLRecordCertCLI extends CLI {

    public CACRLRecordCertCLI(CLI parent) {
        super("cert", "CRL revoked certificate management commands", parent);

        addModule(new CACRLRecordCertFindCLI(this));
    }
}
