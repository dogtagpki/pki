//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.SimpleProperties;

public class CAConfig extends EngineConfig {

    public CAConfig(ConfigStorage storage) {
        super(storage);
    }

    public CAConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
