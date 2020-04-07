//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.function.Consumer;
import java.util.Properties;

/**
 * Default values for ACME engine configuration.
 *
 * No updates are ever performed.
 */
class ACMEEngineConfigDefaultSource extends ACMEEngineConfigSource {
    Consumer<Boolean> setEnabled;

    public void init(Properties _cfg, Consumer<Boolean> setEnabled) {
        setEnabled.accept(true);
    }
}
