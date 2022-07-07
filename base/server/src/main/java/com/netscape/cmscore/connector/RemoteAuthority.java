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

import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStore;

/**
 * This represents a remote authority that can be
 * a certificate manager, or key recovery manager or
 * some other manager.
 */
public class RemoteAuthority {

    String mHost = null;
    int mPort = -1;
    String mURI = null;
    Hashtable<String, String> mURIs = new Hashtable<>();
    String mContentType = null;
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

    public RemoteAuthority(String host, int port, Hashtable<String, String>uris, int timeout) {
        mHost = host;
        mPort = port;
        mURIs = uris;
        mTimeout = timeout;
    }

    public RemoteAuthority(String host, int port, Hashtable<String, String>uris, int timeout, String contentType) {
        mHost = host;
        mPort = port;
        mURIs = uris;
        mTimeout = timeout;
        if (contentType.equals(""))
            mContentType = null;
        else
            mContentType = contentType;
    }

    public RemoteAuthority() {
    }

/*cfu what TODO?*/
    public void init(ConfigStore c) throws EBaseException {
        mHost = c.getString("host");
        mPort = c.getInteger("port");
        mURI = c.getString("uri");
        mTimeout = c.getInteger("timeout");
    }

    /**
     * Retrieves the host name of the remote Authority.
     *
     * @return String with the name of host of remote Authority.
     */
    public String getHost() {
        return mHost;
    }

    /**
     * Retrieves the port number of the remote Authority.
     *
     * @return Int with port number of remote Authority.
     */
    public int getPort() {
        return mPort;
    }

    /**
     * Retrieves the URI of the remote Authority.
     *
     * @return String with URI of remote Authority.
     */
    public String getURI() {
        return mURI;
    }

    /**
     * Retrieves a URI by operation (multi-URI support)
     *
     * @param name operation to determine the receiving servlet
     */
    public String getURI(String name) {
        return mURIs.get(name);
    }

    /**
     * Retrieves the list of URIs supported by the remote Authority
     * (multi-URI support)
     */
    public Hashtable<String, String> getURIs() {
        return mURIs;
    }

    /**
     * Retrieves the timeout value for the connection to the remote Authority.
     *
     * @return In with remote Authority timeout value.
     */
    public int getTimeout() {
        return mTimeout;
    }

    /**
     * Retrieves the Content-Type value of the connection to the Remote Authority.
     *
     * @return String with Content-Type, if it was set
     */
    public String getContentType() {
        return mContentType;
    }
}
