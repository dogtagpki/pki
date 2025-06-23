//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.ca.CACertClient;

/**
 * @author Endi S. Dewata
 */
public class CACRLCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACRLCLI.class);

    public CACertClient certClient;

    public CACRLCLI(CLI parent) {
        super("crl", "CRL management commands", parent);

        addModule(new CACRLUpdateCLI(this));
    }
}
