// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class SubsystemConfig extends PropConfigStore {

    public SubsystemConfig(ConfigStorage storage) {
        super(storage);
    }

    public SubsystemConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getID() throws EBaseException {
        return getString("id");
    }

    public String getClassName() throws EBaseException {
        return getString("class");
    }

    public boolean isEnabled() throws EBaseException {
        return getBoolean("enabled", true);
    }

    public void setEnabled(boolean enabled) throws EBaseException {
        putBoolean("enabled", enabled);
    }
}
