//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.usrgrp;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

public class UGSubsystemConfig extends ConfigStore {

    public UGSubsystemConfig() {
    }

    public UGSubsystemConfig(ConfigStorage storage) {
        super(storage);
    }

    public UGSubsystemConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public LDAPConfig getLDAPConfig() throws EBaseException {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
