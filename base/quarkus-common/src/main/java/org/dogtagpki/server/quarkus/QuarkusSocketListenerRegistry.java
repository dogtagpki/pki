//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.ArrayList;
import java.util.List;

import com.netscape.cmscore.apps.SocketListenerRegistry;

import org.mozilla.jss.ssl.SSLSocketListener;

/**
 * Quarkus-based implementation of SocketListenerRegistry.
 *
 * In Quarkus deployments, SSL/TLS is handled by Vert.x rather
 * than TomcatJSS. This implementation manages socket listeners
 * directly without TomcatJSS.
 */
public class QuarkusSocketListenerRegistry implements SocketListenerRegistry {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(
            QuarkusSocketListenerRegistry.class);

    private final List<SSLSocketListener> listeners = new ArrayList<>();

    @Override
    public void addSocketListener(SSLSocketListener listener) {
        logger.info("QuarkusSocketListenerRegistry: Registering socket listener: {}",
                listener.getClass().getName());
        listeners.add(listener);
    }

    @Override
    public void removeSocketListener(SSLSocketListener listener) {
        logger.info("QuarkusSocketListenerRegistry: Removing socket listener: {}",
                listener.getClass().getName());
        listeners.remove(listener);
    }

    public List<SSLSocketListener> getListeners() {
        return listeners;
    }
}
