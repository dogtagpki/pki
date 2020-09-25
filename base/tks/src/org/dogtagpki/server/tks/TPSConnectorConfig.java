//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.SimpleProperties;

public class TPSConnectorConfig extends EngineConfig {

    public TPSConnectorConfig(ConfigStorage storage) {
        super(storage);
    }

    public TPSConnectorConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
