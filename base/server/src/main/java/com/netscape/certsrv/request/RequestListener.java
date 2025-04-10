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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.request;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * An class that defines abilities of request listener,
 */
public abstract class RequestListener {

    protected CMSEngine engine;

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public void init(ConfigStore config) throws EBaseException {
        init(null, config);
    }

    /**
     * Initializes request listener for the specific subsystem
     * and configuration store.
     *
     * @param sub subsystem
     * @param config configuration store
     */
    public abstract void init(Subsystem sub, ConfigStore config) throws EBaseException;

    /**
     * Accepts request.
     *
     * @param request request
     */
    public abstract void accept(Request request);

    /**
     * Sets attribute.
     *
     * @param name attribute name
     * @param val attribute value
     */
    public abstract void set(String name, String val);
}
