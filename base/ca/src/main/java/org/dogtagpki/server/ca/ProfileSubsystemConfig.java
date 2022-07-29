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
 * Provides profile.* parameters.
 */
public class ProfileSubsystemConfig extends ConfigStore {

    public ProfileSubsystemConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileSubsystemConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
