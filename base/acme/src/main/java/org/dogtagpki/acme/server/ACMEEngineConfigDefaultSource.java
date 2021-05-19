//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.Properties;

/**
 * Default values for ACME engine configuration.
 *
 * No updates are ever performed.
 */
class ACMEEngineConfigDefaultSource extends ACMEEngineConfigSource {

    @Override
    public void init(Properties _cfg) {
        enabledConsumer.accept(true);
        wildcardConsumer.accept(true);
    }
}
