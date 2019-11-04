//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.SimpleProperties;

public class OCSPConfig extends EngineConfig {

    public OCSPConfig(ConfigStorage storage) {
        super(storage);
    }

    public OCSPConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
