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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.tps.server;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSAuthority implements IAuthority, ISubsystem {

    public ILogger logger = CMS.getLogger();

    public String id;
    public String nickname;
    public ISubsystem owner;
    public IConfigStore config;

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) throws EBaseException {
        this.id = id;
    }

    @Override
    public void init(ISubsystem owner, IConfigStore config) throws EBaseException {
        this.owner = owner;
        this.config = config;
    }

    @Override
    public void startup() throws EBaseException {
    }

    @Override
    public void shutdown() {
    }

    @Override
    public IConfigStore getConfigStore() {
        return config;
    }

    @Override
    public IRequestQueue getRequestQueue() {
        return null;
    }

    @Override
    public void registerRequestListener(IRequestListener listener) {
    }

    @Override
    public void registerPendingListener(IRequestListener listener) {
    }

    @Override
    public void log(int level, String msg) {
        logger.log(ILogger.EV_SYSTEM, ILogger.S_TPS, level, msg);
    }

    @Override
    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    @Override
    public String getOfficialName() {
        return "tps";
    }

}
