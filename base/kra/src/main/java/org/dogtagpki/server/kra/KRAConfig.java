//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class KRAConfig extends ConfigStore {

    public KRAConfig(ConfigStorage storage) {
        super(storage);
    }

    public KRAConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
