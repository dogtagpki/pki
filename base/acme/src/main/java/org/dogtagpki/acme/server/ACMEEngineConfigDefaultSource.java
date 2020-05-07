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
    public void init(Properties _cfg, Consumer<Boolean> setEnabled, Consumer<Boolean> setWildcard) {
        setEnabled.accept(true);
        setWildcard.accept(true);
    }
}
