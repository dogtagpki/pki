//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldapconn;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class PKISocketConfig extends PropConfigStore {

    public PKISocketConfig() {
    }

    public PKISocketConfig(ConfigStorage storage) {
        super(storage);
    }

    public PKISocketConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean isKeepAlive() throws EBaseException {
        return getBoolean("keepAlive", true);
    }
}
