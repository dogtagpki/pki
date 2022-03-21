//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package com.netscape.cmscore.apps;

import com.netscape.cmscore.base.ConfigStore;

public abstract class SubsystemListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SubsystemListener.class);

    public void init(ConfigStore config) throws Exception {
    }

    public void subsystemStarted() throws Exception {
    }
}
