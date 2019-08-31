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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class SubsystemsConfig extends PropConfigStore {

    public SubsystemsConfig(ConfigStorage storage) {
        super(storage);
    }

    public SubsystemsConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public Collection<String> getSubsystemNames() {

        List<String> names = new ArrayList<>();
        Map<String, String> map = getProperties();

        for (String name : map.keySet()) {
            int i = name.indexOf('.'); // substores have "."
            if (i < 0) continue;

            name = name.substring(0, i);
            if (names.contains(name)) continue;

            names.add(name);
        }

        return names;
    }

    public SubsystemConfig getSubsystemConfig(String name) {

        String fullname = getFullName(name);
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new SubsystemConfig(fullname, mSource);

        } else {
            return new SubsystemConfig(reference, mSource);
        }
    }
}
