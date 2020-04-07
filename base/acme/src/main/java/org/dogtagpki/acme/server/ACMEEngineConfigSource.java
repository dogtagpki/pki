//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.function.Consumer;
import java.util.Properties;

/**
 * Source of ACME engine configuration.
 *
 * This class allows for dynamic (re)configuration of the ACME service.
 *
 * Sinks configuration values to the setBlah methods when the configuration
 * is first read, and when changes to those values are detected.
 */
abstract class ACMEEngineConfigSource {
    Consumer<Boolean> setEnabled;

    public abstract void init(
        Properties cfg,
        Consumer<Boolean> setEnabled)
        throws Exception;

    void init(Consumer<Boolean> setEnabled) {
        this.setEnabled = setEnabled;
    }

    /**
     * Shut down the engine config source.  Subclasses that e.g. create
     * background threads should override this.
     */
    public void shutdown() {
    }
}
