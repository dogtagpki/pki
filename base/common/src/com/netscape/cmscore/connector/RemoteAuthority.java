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
package com.netscape.cmscore.connector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.connector.IRemoteAuthority;

public class RemoteAuthority implements IRemoteAuthority {
    String mHost = null;
    int mPort = -1;
    String mURI = null;
    int mTimeout = 0;

    /**
     * host parameter can be:
     * "directory.knowledge.com"
     * "199.254.1.2"
     * "directory.knowledge.com:1050 people.catalog.com 199.254.1.2"
     */
    public RemoteAuthority(String host, int port, String uri, int timeout) {
        mHost = host;
        mPort = port;
        mURI = uri;
        mTimeout = timeout;
    }

    public RemoteAuthority() {
    }

    public void init(IConfigStore c)
            throws EBaseException {
        mHost = c.getString("host");
        mPort = c.getInteger("port");
        mURI = c.getString("uri");
        mTimeout = c.getInteger("timeout");
    }

    public String getHost() {
        return mHost;
    }

    public int getPort() {
        return mPort;
    }

    public String getURI() {
        return mURI;
    }

    public int getTimeout() {
        return mTimeout;
    }
}
