//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.range;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.SubsystemCLI;

public class RangeCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RangeCLI.class);

    public SubsystemCLI subsystemCLI;

    public RangeCLI(SubsystemCLI subsystemCLI) {
        super("range", "Range management commands", subsystemCLI);

        this.subsystemCLI = subsystemCLI;

        addModule(new RangeRequestCLI(this));
    }
}
