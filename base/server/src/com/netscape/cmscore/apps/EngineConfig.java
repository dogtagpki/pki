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

public class EngineConfig extends PropConfigStore {

    public EngineConfig(ConfigStorage storage) {
        super(storage);
    }

    public String getHostname() throws EBaseException {
        return getString("machineName");
    }

    public void setHostname(String hostname) throws EBaseException {
        putString("machineName", hostname);
    }

    public String getInstanceID() throws EBaseException {
        return getString("instanceId");
    }

    public void setInstanceID(String instanceID) throws EBaseException {
        putString("instanceId", instanceID);
    }

    public String getInstanceDir() throws EBaseException {
        return getString("instanceRoot");
    }

    public void setInstanceDir(String instanceDir) {
        putString("instanceRoot", instanceDir);
    }

    public String getType() throws EBaseException {
        return getString("cs.type");
    }

    public void setType(String type) throws EBaseException {
        putString("cs.type", type);
    }

    public int getState() throws EBaseException {
        return getInteger("cs.state");
    }

    public void setState(int state) {
        putInteger("cs.state", state);
    }
}
