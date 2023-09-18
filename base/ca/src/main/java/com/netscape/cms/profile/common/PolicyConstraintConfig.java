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
 * Provides policy constraint configuration.
 */
public class PolicyConstraintConfig extends ConfigStore {

    public PolicyConstraintConfig() {
    }

    public PolicyConstraintConfig(ConfigStorage storage) {
        super(storage);
    }

    public PolicyConstraintConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getClassID() throws EBaseException {
        return getString("class_id");
    }

    public void setClassID(String classID) {
        putString("class_id", classID);
    }

    public String getConstraintName() throws EBaseException {
        return getString("name");
    }

    public void setConstraintName(String name) {
        putString("name", name);
    }

    public String getDescription() throws EBaseException {
        return getString("description");
    }

    public void setDescription(String description) {
        putString("description", description);
    }
}
