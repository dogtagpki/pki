//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.Properties;
import java.util.function.Consumer;

/**
 * Source of ACME engine configuration.
 *
 * This class allows for dynamic (re)configuration of the ACME service.
 *
 * Sinks configuration values to the setBlah methods when the configuration
 * is first read, and when changes to those values are detected.
 */
abstract class ACMEEngineConfigSource {

    Consumer<Boolean> enabledConsumer;
    Consumer<Boolean> wildcardConsumer;

    Consumer<Boolean> getEnabledConsumer() {
        return enabledConsumer;
    }

    void setEnabledConsumer(Consumer<Boolean> enabledConsumer) {
        this.enabledConsumer = enabledConsumer;
    }

    Consumer<Boolean> getWildcardConsumer() {
        return wildcardConsumer;
    }

    void setWildcardConsumer(Consumer<Boolean> wildcardConsumer) {
        this.wildcardConsumer = wildcardConsumer;
    }

    public abstract void init(Properties cfg) throws Exception;

    /**
     * Shut down the engine config source.  Subclasses that e.g. create
     * background threads should override this.
     */
    public void shutdown() {
    }
}
