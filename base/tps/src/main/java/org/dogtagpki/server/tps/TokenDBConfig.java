//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides tokendb.* parameters.
 */
public class TokenDBConfig extends ConfigStore {

    public TokenDBConfig(ConfigStorage storage) {
        super(storage);
    }

    public TokenDBConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
