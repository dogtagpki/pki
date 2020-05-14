//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tps.config;

import com.netscape.cmstools.cli.SubsystemCLI;

public class TPSConfigCLI extends ConfigCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSConfigCLI.class);

    public TPSConfigCLI(SubsystemCLI subsystemCLI) {
        super("config", "Configuration management commands", subsystemCLI);

        addModule(new ConfigModifyCLI(this));
        addModule(new ConfigShowCLI(this));
    }
}
