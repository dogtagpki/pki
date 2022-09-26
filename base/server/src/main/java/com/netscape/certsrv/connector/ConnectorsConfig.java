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
 * Provides <subsystem>.connector.* parameters.
 */
public class ConnectorsConfig extends ConfigStore {

    public ConnectorsConfig(ConfigStorage storage) {
        super(storage);
    }

    public ConnectorsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
