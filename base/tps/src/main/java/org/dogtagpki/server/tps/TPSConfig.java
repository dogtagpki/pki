//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class TPSConfig extends ConfigStore {

    public TPSConfig(ConfigStorage storage) {
        super(storage);
    }

    public TPSConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
