//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.connector;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides <subsystem>.connector.<id>.* parameters.
 */
public class ConnectorConfig extends ConfigStore {

    public ConnectorConfig(ConfigStorage storage) {
        super(storage);
    }

    public ConnectorConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
