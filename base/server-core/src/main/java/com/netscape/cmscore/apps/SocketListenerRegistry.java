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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import org.mozilla.jss.ssl.SSLSocketListener;

/**
 * Container-agnostic interface for registering SSL socket listeners.
 *
 * In Tomcat deployments, this delegates to TomcatJSS.
 * In Quarkus deployments, this initializes JSS directly
 * or uses a Vert.x-based SSL handler.
 */
public interface SocketListenerRegistry {

    /**
     * Register an SSL socket listener for connection event monitoring.
     */
    void addSocketListener(SSLSocketListener listener);

    /**
     * Remove a previously registered SSL socket listener.
     */
    void removeSocketListener(SSLSocketListener listener);
}
