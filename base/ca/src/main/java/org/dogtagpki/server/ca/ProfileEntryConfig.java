//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides profile.<name>.* parameters.
 */
public class ProfileEntryConfig extends ConfigStore {

    public ProfileEntryConfig() {
    }

    public ProfileEntryConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileEntryConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
