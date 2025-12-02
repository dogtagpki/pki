//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class SDCLI extends CLI {

    public SDCLI(SubsystemCLI subsystemCLI) {
        super("sd", "Security domain commands", subsystemCLI);

        addModule(new SDJoinCLI(this));
        addModule(new SDLeaveCLI(this));
    }

    @Override
    public String getManPage() {
        return "pki-securitydomain";
    }
}
