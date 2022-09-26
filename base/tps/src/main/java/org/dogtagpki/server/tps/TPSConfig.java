//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides tps.* parameters.
 */
public class TPSConfig extends ConfigStore {

    public TPSConfig(ConfigStorage storage) {
        super(storage);
    }

    public TPSConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns tps.connector.* parameters.
     */
    public ConnectorsConfig getConnectorsConfig() {
        return getSubStore("connector", ConnectorsConfig.class);
    }
}
