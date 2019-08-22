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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

public class SubsystemInfo {

    public String id;
    public boolean enabled;
    public boolean updateIdOnInit;

    public SubsystemInfo(String id) {
        this(id, true, false);
    }

    public SubsystemInfo(String id, boolean enabled, boolean updateIdOnInit) {
        this.id = id;
        this.enabled = enabled;
        this.updateIdOnInit = updateIdOnInit;
    }

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isUpdateIdOnInit() {
        return updateIdOnInit;
    }

    public void setUpdateIdOnInit(boolean updateIdOnInit) {
        this.updateIdOnInit = updateIdOnInit;
    }
}
