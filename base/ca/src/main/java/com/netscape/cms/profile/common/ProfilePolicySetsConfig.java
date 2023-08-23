//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.common;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides profile policy sets configuration.
 */
public class ProfilePolicySetsConfig extends ConfigStore {

    public ProfilePolicySetsConfig() {
    }

    public ProfilePolicySetsConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfilePolicySetsConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns IDs of profile policy sets.
     */
    public String getList() throws EBaseException {
        return getString("list", "");
    }

    public void setList(String list) {
        putString("list", list);
    }

    /**
     * Returns profile policy set configuration.
     */
    public ProfilePolicySetConfig getPolicySetConfig(String id) {
        return getSubStore(id, ProfilePolicySetConfig.class);
    }

    public void removePolicySetConfig(String id) {
        removeSubStore(id);
    }
}
