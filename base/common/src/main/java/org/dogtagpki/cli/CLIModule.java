//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.cli;

import java.lang.reflect.Constructor;

/**
 * @author Endi S. Dewata
 */
public class CLIModule {

    public CLI parent;
    public String className;
    public CLI cli;

    public CLIModule(CLI parent, String className) {
        this.parent = parent;
        this.className = className;
    }

    public CLIModule(CLI parent, CLI cli) {
        this.parent = parent;
        this.className = cli.getClass().getName();
        this.cli = cli;
    }

    public CLI getCLI() throws Exception {

        if (cli != null) return cli;

        Class<? extends CLI> clazz = Class.forName(className).asSubclass(CLI.class);
        Constructor<? extends CLI> constructor = clazz.getConstructor(CLI.class);
        cli = constructor.newInstance(parent);

        return cli;
    }
}
